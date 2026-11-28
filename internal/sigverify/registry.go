package sigverify

import (
	"context"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
)

// maxSignatureBlob caps bundle and payload downloads; real ones are a few KiB.
const maxSignatureBlob = 1 << 20

// Fetcher reads signature manifests and their layers from a registry.
type Fetcher interface {
	FetchManifestReference(ctx context.Context, repo, reference string) (*oci.Manifest, error)
	FetchBlob(ctx context.Context, repo string, desc ocispec.Descriptor, maxSize int64) ([]byte, error)
}

// Signature verifies one signature attached to subject. Only cosign
// signatures are verified; a bundle has to hold a cosign/sign statement or a
// message signature to count as a signature of the subject.
func (v *Verifier) Signature(ctx context.Context, f Fetcher, repo string, subject digest.Digest, ref oci.SignatureRef) Result {
	r := v.Attached(ctx, f, repo, subject, ref)
	if r.Status == Verified && r.PredicateType != "" && r.PredicateType != oci.PredicateCosignSign {
		return r.invalid("bundle holds a %s statement, not a signature", r.PredicateType)
	}
	return r
}

// Attached verifies a signed artifact attached to subject, a signature or an
// attestation, and reports what it holds in PredicateType.
func (v *Verifier) Attached(ctx context.Context, f Fetcher, repo string, subject digest.Digest, ref oci.SignatureRef) Result {
	res := newResult(ref.Format)
	if ref.Format != oci.FormatCosign {
		return res.unverified("%s signatures are not verified yet", ref.Format)
	}
	m, err := f.FetchManifestReference(ctx, repo, ref.Reference())
	if err != nil {
		return res.unverified("cannot fetch signature: %v", err)
	}
	return v.Manifest(ctx, f, repo, subject, m)
}

// Signatures verifies all signatures attached to subject and returns one
// result per signature.
func (v *Verifier) Signatures(ctx context.Context, f Fetcher, repo string, subject digest.Digest, refs []oci.SignatureRef) []Result {
	out := make([]Result, len(refs))
	for i, ref := range refs {
		out[i] = v.Signature(ctx, f, repo, subject, ref)
	}
	return out
}

// Manifest verifies a cosign manifest for subject: a referrer with a Sigstore
// bundle (signature or attestation) or a legacy .sig manifest, which may
// hold several signatures. One valid signature makes the manifest verified.
func (v *Verifier) Manifest(ctx context.Context, f Fetcher, repo string, subject digest.Digest, m *oci.Manifest) Result {
	var results []Result
	for _, l := range m.Layers {
		var verifyLayer func([]byte) Result
		switch {
		case strings.HasPrefix(l.MediaType, "application/vnd.dev.sigstore.bundle"):
			verifyLayer = func(b []byte) Result { return v.VerifyBundle(b, subject) }
		case l.MediaType == MediaTypeSimpleSigning:
			verifyLayer = func(b []byte) Result { return v.VerifyLegacy(b, l.Annotations, subject) }
		default:
			continue
		}
		data, err := f.FetchBlob(ctx, repo, l, maxSignatureBlob)
		if err != nil {
			results = append(results, newResult(oci.FormatCosign).unverified("cannot fetch signature: %v", err))
			continue
		}
		results = append(results, verifyLayer(data))
	}
	if len(results) == 0 {
		return newResult(oci.FormatCosign).unverified("no cosign signature or bundle layer")
	}
	return Best(results)
}
