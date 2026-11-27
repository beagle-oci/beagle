package oci

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Signature formats reported by SignatureFormat.
const (
	FormatCosign   = "cosign"
	FormatNotation = "notation"
)

// Attachments summarizes the artifacts attached to a manifest.
type Attachments struct {
	// Signatures lists the signature formats found, e.g. "cosign".
	Signatures []string
	// Kinds counts the other attached artifacts (SBOMs, attestations, ...).
	Kinds map[Kind]int
}

// Signed reports whether at least one signature is attached.
func (a Attachments) Signed() bool { return len(a.Signatures) > 0 }

func (a *Attachments) add(k Kind, format string) {
	if k == KindSignature {
		if format == "" {
			format = "other"
		}
		if !slices.Contains(a.Signatures, format) {
			a.Signatures = append(a.Signatures, format)
			slices.Sort(a.Signatures)
		}
		return
	}
	if a.Kinds == nil {
		a.Kinds = map[Kind]int{}
	}
	a.Kinds[k]++
}

// SignatureFormat returns the signature format of a referrer descriptor:
// FormatCosign for cosign signatures and sigstore bundles, FormatNotation
// for Notary Project signatures, or "" if it is not a signature.
func SignatureFormat(d ocispec.Descriptor) string {
	if ClassifyDescriptor(d) != KindSignature {
		return ""
	}
	if classifyNotation(d.ArtifactType) {
		return FormatNotation
	}
	return FormatCosign
}

func classifyNotation(t string) bool {
	return t == "application/vnd.cncf.notary.signature"
}

// Attachments lists the referrers of desc and the cosign legacy tags among
// tags that point at it. It costs one referrers request; cosign tags are
// matched by name only.
func (c *Client) Attachments(ctx context.Context, repo string, desc ocispec.Descriptor, tags []string) (Attachments, error) {
	var a Attachments
	for _, st := range CosignTagsFor(desc.Digest, tags) {
		a.add(st.Kind, FormatCosign)
	}
	refs, err := c.Referrers(ctx, repo, desc)
	for _, r := range refs {
		a.add(ClassifyDescriptor(r), SignatureFormat(r))
	}
	return a, err
}

// Created returns when the content of a manifest was built: the
// org.opencontainers.image.created annotation if present, otherwise the
// created field of the image config. For an index the first platform
// manifest is used. It returns the zero time if nothing is known.
func (c *Client) Created(ctx context.Context, repo string, m *Manifest) (time.Time, error) {
	if t, ok := parseTime(m.Annotations[ocispec.AnnotationCreated]); ok {
		return t, nil
	}
	if m.IsIndex() {
		for _, d := range m.Manifests {
			if d.Annotations[AnnotationDockerReferenceType] == "attestation-manifest" || !IsManifestMediaType(d.MediaType) {
				continue
			}
			if t, ok := parseTime(d.Annotations[ocispec.AnnotationCreated]); ok {
				return t, nil
			}
			child, err := c.FetchManifest(ctx, repo, d)
			if err != nil {
				return time.Time{}, err
			}
			if child.IsIndex() {
				return time.Time{}, nil
			}
			return c.Created(ctx, repo, child)
		}
		return time.Time{}, nil
	}
	if m.Config == nil {
		return time.Time{}, nil
	}
	switch m.Config.MediaType {
	case ocispec.MediaTypeImageConfig, MediaTypeDockerConfig:
	default:
		return time.Time{}, nil
	}
	data, err := c.FetchBlob(ctx, repo, *m.Config, DefaultMaxBlobSize)
	if err != nil {
		return time.Time{}, err
	}
	var cfg struct {
		Created string `json:"created"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return time.Time{}, nil
	}
	t, _ := parseTime(cfg.Created)
	return t, nil
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() || t.Year() < 1980 {
		// Reproducible builds often use the Unix epoch; treat it as unknown.
		return time.Time{}, false
	}
	return t, true
}
