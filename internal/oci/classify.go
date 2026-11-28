package oci

import (
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Kind is beagle's coarse classification of a manifest, used for labels and
// colors in the UI.
type Kind int

// Known kinds.
const (
	KindUnknown Kind = iota
	KindIndex
	KindImage
	KindSignature
	KindAttestation
	KindSBOM
	KindVulnReport
	KindVEX
	KindHelmChart
	KindArtifact
	// KindReferrersIndex is the index stored under the OCI 1.1 referrers
	// tag schema (sha256-<hex>) by registries without the referrers API.
	KindReferrersIndex

	// Blob kinds for the config and layers listed in a manifest.
	KindConfig
	KindLayer
	KindEmpty
)

// Annotations used to classify content.
const (
	AnnotationDockerReferenceType   = "vnd.docker.reference.type"
	AnnotationDockerReferenceDigest = "vnd.docker.reference.digest"
	AnnotationSigstorePredicateType = "dev.sigstore.bundle.predicateType"
	AnnotationSigstoreContent       = "dev.sigstore.bundle.content"
)

// PredicateCosignSign is the in-toto predicate type cosign (v2 with
// --new-bundle-format, v3 by default) uses for plain image signatures: a DSSE
// envelope whose statement names the image digest as its subject.
const PredicateCosignSign = "https://sigstore.dev/cosign/sign/v1"

func (k Kind) String() string {
	switch k {
	case KindIndex:
		return "index"
	case KindImage:
		return "image"
	case KindSignature:
		return "signature"
	case KindAttestation:
		return "attestation"
	case KindSBOM:
		return "sbom"
	case KindVulnReport:
		return "vuln-report"
	case KindVEX:
		return "vex"
	case KindHelmChart:
		return "helm-chart"
	case KindArtifact:
		return "artifact"
	case KindReferrersIndex:
		return "referrers"
	case KindConfig:
		return "config"
	case KindLayer:
		return "layer"
	case KindEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// ClassifyDescriptor classifies a manifest from its descriptor alone, as
// returned by the referrers API or listed in an index.
func ClassifyDescriptor(d ocispec.Descriptor) Kind {
	if d.Annotations[AnnotationDockerReferenceType] == "attestation-manifest" {
		return KindAttestation
	}
	if d.ArtifactType != "" {
		if k := classifyType(d.ArtifactType, d.Annotations); k != KindUnknown {
			return k
		}
		return KindArtifact
	}
	if IsIndexMediaType(d.MediaType) {
		return KindIndex
	}
	if IsManifestMediaType(d.MediaType) {
		return KindImage
	}
	return KindUnknown
}

// ClassifyManifest classifies a fetched manifest. It looks at the artifact
// type first and falls back to layer media types, which is how legacy cosign
// signatures and attestations are recognized.
func ClassifyManifest(m *Manifest) Kind {
	ann := mergeAnnotations(m.Descriptor.Annotations, m.Annotations)
	if ann[AnnotationDockerReferenceType] == "attestation-manifest" {
		return KindAttestation
	}
	at := m.EffectiveArtifactType()
	if at != "" {
		if k := classifyType(at, ann); k != KindUnknown {
			return k
		}
	}
	if m.IsIndex() {
		if at != "" {
			return KindArtifact
		}
		return KindIndex
	}
	for _, l := range m.Layers {
		if k := classifyType(l.MediaType, mergeAnnotations(ann, l.Annotations)); k != KindUnknown {
			return k
		}
	}
	if at != "" {
		return KindArtifact
	}
	return KindImage
}

// ClassifyMediaType classifies the media type of a blob listed in a manifest
// (config or layer) or an artifact type. Supply chain and Helm types win;
// plain image configs, image layers and the OCI empty descriptor get their
// own kinds. It returns KindUnknown for anything not recognized.
func ClassifyMediaType(mediaType string) Kind {
	if k := classifyType(mediaType, nil); k != KindUnknown {
		return k
	}
	switch mt := strings.ToLower(mediaType); {
	case mt == ocispec.MediaTypeImageConfig, mt == MediaTypeDockerConfig:
		return KindConfig
	case mt == ocispec.MediaTypeEmptyJSON:
		return KindEmpty
	case strings.HasPrefix(mt, "application/vnd.oci.image.layer."),
		strings.HasPrefix(mt, "application/vnd.docker.image.rootfs."):
		return KindLayer
	}
	return KindUnknown
}

func classifyType(t string, ann map[string]string) Kind {
	t = strings.ToLower(t)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(t, s) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.HasPrefix(t, "application/vnd.dev.sigstore.bundle"):
		// cosign stores signatures and attestations as sigstore bundles. Image
		// signatures are DSSE envelopes with the cosign/sign predicate (or, in
		// older bundles, message signatures); other predicates are attestations.
		pt := ann[AnnotationSigstorePredicateType]
		switch {
		case pt == PredicateCosignSign:
			return KindSignature
		case pt != "" || ann[AnnotationSigstoreContent] == "dsse-envelope":
			return KindAttestation
		}
		return KindSignature
	case has("notary.signature", "cosign.artifact.sig", "cosign.simplesigning", "pgp-signature"):
		return KindSignature
	case has("in-toto", "dsse", "attestation", "provenance", "slsa", "cosign.artifact.att"):
		return KindAttestation
	case has("spdx", "cyclonedx", "sbom", "syft"):
		return KindSBOM
	case has("openvex", "csaf", "vex"):
		return KindVEX
	case has("sarif", "vuln", "trivy", "grype"):
		return KindVulnReport
	case has("helm.config", "helm.chart"):
		return KindHelmChart
	}
	return KindUnknown
}

func mergeAnnotations(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
