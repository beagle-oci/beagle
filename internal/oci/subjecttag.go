package oci

import (
	"strings"

	"github.com/opencontainers/go-digest"
)

// Tag schemes that encode a subject digest in the tag name.
const (
	// SchemeCosign is cosign's pre-OCI-1.1 convention:
	// sha256-<hex>.sig, sha256-<hex>.att and sha256-<hex>.sbom.
	SchemeCosign = "cosign"
	// SchemeReferrersTag is the OCI 1.1 referrers tag schema used by
	// registries without the referrers API: sha256-<hex>.
	SchemeReferrersTag = "referrers-tag"
)

// SubjectTag is a tag whose name points at another manifest.
type SubjectTag struct {
	Tag     string
	Subject digest.Digest
	Kind    Kind
	Scheme  string
}

// ParseSubjectTag recognizes cosign legacy tags and OCI referrers fallback
// tags.
func ParseSubjectTag(tag string) (SubjectTag, bool) {
	alg, rest, ok := strings.Cut(tag, "-")
	if !ok {
		return SubjectTag{}, false
	}
	switch digest.Algorithm(alg) {
	case digest.SHA256, digest.SHA512:
	default:
		return SubjectTag{}, false
	}
	encoded, suffix, _ := strings.Cut(rest, ".")
	d := digest.NewDigestFromEncoded(digest.Algorithm(alg), encoded)
	if d.Validate() != nil {
		return SubjectTag{}, false
	}
	st := SubjectTag{Tag: tag, Subject: d, Scheme: SchemeCosign}
	switch suffix {
	case "":
		st.Kind = KindReferrersIndex
		st.Scheme = SchemeReferrersTag
	case "sig":
		st.Kind = KindSignature
	case "att":
		st.Kind = KindAttestation
	case "sbom":
		st.Kind = KindSBOM
	default:
		return SubjectTag{}, false
	}
	return st, true
}

// CosignTagsFor returns the cosign legacy tags among tags that point at
// subject. Referrers fallback tags are excluded: oras-go already reads them
// when listing referrers.
func CosignTagsFor(subject digest.Digest, tags []string) []SubjectTag {
	var out []SubjectTag
	for _, t := range tags {
		st, ok := ParseSubjectTag(t)
		if ok && st.Scheme == SchemeCosign && st.Subject == subject {
			out = append(out, st)
		}
	}
	return out
}
