package ui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/sigverify"
)

// verification is the signature state the manifest view shows: for an image
// whether it is signed, for a signature whether it checks out.
type verification struct {
	label  string
	state  loadState
	none   bool
	result sigverify.Result
}

type manifestVerifiedMsg struct {
	viewID int
	none   bool
	result sigverify.Result
}

func (m manifestVerifiedMsg) target() int { return m.viewID }

// summaryField is a labeled line in a view's summary.
type summaryField struct {
	label, value string
	style        *lipgloss.Style
}

// attachedSignatures finds the signatures of desc: its referrers and a
// cosign legacy sha256-<hex>.sig tag.
func attachedSignatures(ctx context.Context, c *oci.Client, repo string, desc ocispec.Descriptor) ([]oci.SignatureRef, error) {
	var tags []string
	legacy := strings.Replace(desc.Digest.String(), ":", "-", 1) + ".sig"
	if _, err := c.Resolve(ctx, repo, legacy); err == nil {
		tags = append(tags, legacy)
	}
	a, err := c.Attachments(ctx, repo, desc, tags)
	return a.SignatureRefs, err
}

// hasCosignLayer reports whether m holds a Sigstore bundle or a legacy cosign
// signature, the formats beagle verifies.
func hasCosignLayer(m *oci.Manifest) bool {
	for _, l := range m.Layers {
		if strings.HasPrefix(l.MediaType, "application/vnd.dev.sigstore.bundle") || l.MediaType == sigverify.MediaTypeSimpleSigning {
			return true
		}
	}
	return false
}

// signatureSubject returns what a signature or attestation manifest is
// about: its subject field, or the digest in a cosign legacy tag.
func signatureSubject(m *oci.Manifest, reference string) (digest.Digest, bool) {
	if m.Subject != nil {
		return m.Subject.Digest, true
	}
	if st, ok := oci.ParseSubjectTag(reference); ok && st.Scheme == oci.SchemeCosign {
		return st.Subject, true
	}
	return "", false
}

// startVerify verifies what the manifest view shows, if verification is on:
// the signatures attached to an image or index, or the signature or
// attestation itself.
func (v *manifestView) startVerify(e *env) tea.Cmd {
	m := v.manifest
	if e.verifier == nil || m == nil {
		return nil
	}
	id, repo := v.id(), v.repo
	var run func(ctx context.Context) manifestVerifiedMsg
	switch v.kind {
	case oci.KindImage, oci.KindIndex:
		v.verification = &verification{label: "Signatures"}
		run = func(ctx context.Context) manifestVerifiedMsg {
			refs, err := attachedSignatures(ctx, e.client, repo, m.Descriptor)
			if len(refs) == 0 {
				if err != nil {
					return manifestVerifiedMsg{viewID: id, result: sigverify.Result{Reason: "cannot list referrers: " + err.Error()}}
				}
				return manifestVerifiedMsg{viewID: id, none: true}
			}
			return manifestVerifiedMsg{viewID: id, result: sigverify.Best(e.verifier.Signatures(ctx, e.client, repo, m.Descriptor.Digest, refs))}
		}
	case oci.KindSignature, oci.KindAttestation:
		subject, ok := signatureSubject(m, v.reference)
		notation := m.EffectiveArtifactType() == "application/vnd.cncf.notary.signature"
		if !ok || (!notation && !hasCosignLayer(m)) {
			return nil
		}
		v.verification = &verification{label: "Verification"}
		run = func(ctx context.Context) manifestVerifiedMsg {
			if notation {
				ref := oci.SignatureRef{Format: oci.FormatNotation, Descriptor: m.Descriptor}
				return manifestVerifiedMsg{viewID: id, result: e.verifier.Signature(ctx, e.client, repo, subject, ref)}
			}
			return manifestVerifiedMsg{viewID: id, result: e.verifier.Manifest(ctx, e.client, repo, subject, m)}
		}
	default:
		return nil
	}
	v.verification.state = stateLoading
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		return run(ctx)
	}
}

// fields renders the verification for the manifest summary.
func (vf *verification) fields() []summaryField {
	switch {
	case vf == nil:
		return nil
	case vf.state == stateLoading:
		return []summaryField{{label: vf.label, value: "… verifying"}}
	case vf.none:
		return []summaryField{{label: vf.label, value: "none", style: &styleMuted}}
	}
	r := vf.result
	var status string
	switch r.Status {
	case sigverify.Verified:
		status = "✓ verified (" + r.Format
		if r.PredicateType != "" && r.PredicateType != oci.PredicateCosignSign {
			status += ", " + r.PredicateType
		}
		status += ")"
	case sigverify.Invalid:
		status = "✗ invalid: " + r.Reason
	default:
		status = "? not verified: " + r.Reason
	}
	out := []summaryField{{label: vf.label, value: status, style: verificationStyle(&r)}}
	if r.Status != sigverify.Verified {
		return out
	}
	if r.Signer != "" {
		signer := r.Signer
		if r.Issuer != "" {
			signer += "  (" + r.Issuer + ")"
		}
		out = append(out, summaryField{label: "Signed by", value: signer})
	}
	if r.SourceRepository != "" {
		src := r.SourceRepository
		if rev := r.SourceRevision; rev != "" {
			src += " @ " + rev[:min(len(rev), 12)]
		}
		out = append(out, summaryField{label: "Source", value: src})
	}
	if !r.Time.IsZero() {
		logged := formatTime(r.Time, "")
		if r.LogIndex >= 0 {
			logged += fmt.Sprintf("  (log index %d)", r.LogIndex)
		}
		out = append(out, summaryField{label: "Logged", value: logged})
	}
	return out
}
