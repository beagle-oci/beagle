package ocitest

import (
	"encoding/json"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Fixture describes the content created by Seed.
type Fixture struct {
	Repo       string
	Index      ocispec.Descriptor
	AMD64      ocispec.Descriptor
	ARM64      ocispec.Descriptor
	Signature  ocispec.Descriptor
	SBOM       ocispec.Descriptor
	SBOMSig    ocispec.Descriptor
	Provenance ocispec.Descriptor
	Notation   ocispec.Descriptor
	CosignTag  string
	CosignSig  ocispec.Descriptor
	ChartRepo  string
	Chart      ocispec.Descriptor
}

// Seed fills r with a multi-platform image that carries the usual supply
// chain artifacts: a sigstore bundle signature, an SBOM with its own
// signature, a SLSA provenance attestation, a notation signature on one
// platform and a cosign legacy .sig tag. It also adds a Helm chart.
func Seed(r *Registry) Fixture {
	const repo = "demo/app"
	f := Fixture{Repo: repo, ChartRepo: "demo/chart"}

	image := func(arch string) ocispec.Descriptor {
		cfg, _ := json.Marshal(ocispec.Image{
			Platform: ocispec.Platform{OS: "linux", Architecture: arch},
			Config:   ocispec.ImageConfig{Entrypoint: []string{"/app"}},
			RootFS:   ocispec.RootFS{Type: "layers"},
		})
		cfgDesc := r.PushBlob(repo, ocispec.MediaTypeImageConfig, cfg)
		layer := r.PushBlob(repo, ocispec.MediaTypeImageLayerGzip, []byte("layer-"+arch))
		m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfgDesc, Layers: []ocispec.Descriptor{layer}}
		m.SchemaVersion = 2
		d := r.PushManifest(repo, "", ocispec.MediaTypeImageManifest, m)
		d.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}
		return d
	}
	f.AMD64 = image("amd64")
	f.ARM64 = image("arm64")

	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{f.AMD64, f.ARM64}}
	idx.SchemaVersion = 2
	f.Index = r.PushManifest(repo, "v1.0.0", ocispec.MediaTypeImageIndex, idx)
	r.Tag(repo, "latest", f.Index.Digest)

	f.Signature = PushArtifact(r, repo, f.Index, "application/vnd.dev.sigstore.bundle.v0.3+json",
		map[string]string{"dev.sigstore.bundle.content": "message-signature"}, "application/vnd.dev.sigstore.bundle.v0.3+json", `{"mediaType":"bundle"}`)
	f.SBOM = PushArtifact(r, repo, f.Index, "application/spdx+json", nil, "application/spdx+json", `{"spdxVersion":"SPDX-2.3"}`)
	f.SBOMSig = PushArtifact(r, repo, f.SBOM, "application/vnd.dev.sigstore.bundle.v0.3+json",
		map[string]string{"dev.sigstore.bundle.content": "message-signature"}, "application/vnd.dev.sigstore.bundle.v0.3+json", `{"mediaType":"bundle"}`)
	f.Provenance = PushArtifact(r, repo, f.Index, "application/vnd.dev.sigstore.bundle.v0.3+json",
		map[string]string{
			"dev.sigstore.bundle.content":       "dsse-envelope",
			"dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1",
		}, "application/vnd.dev.sigstore.bundle.v0.3+json", `{"mediaType":"bundle"}`)
	f.Notation = PushArtifact(r, repo, f.AMD64, "application/vnd.cncf.notary.signature", nil, "application/jose+json", `{"payload":"x"}`)

	// cosign < v3 stored signatures under sha256-<hex>.sig as a plain image.
	f.CosignTag = strings.Replace(f.Index.Digest.String(), ":", "-", 1) + ".sig"
	cfg := r.PushBlob(repo, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"","os":"","rootfs":{"type":"layers","diff_ids":[]}}`))
	payload := r.PushBlob(repo, "application/vnd.dev.cosign.simplesigning.v1+json", []byte(`{"critical":{}}`))
	sig := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: []ocispec.Descriptor{payload}}
	sig.SchemaVersion = 2
	f.CosignSig = r.PushManifest(repo, f.CosignTag, ocispec.MediaTypeImageManifest, sig)

	chartCfg := r.PushBlob(f.ChartRepo, "application/vnd.cncf.helm.config.v1+json", []byte(`{"name":"demo","version":"0.1.0"}`))
	chartLayer := r.PushBlob(f.ChartRepo, "application/vnd.cncf.helm.chart.content.v1.tar+gzip", []byte("chart"))
	chart := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: chartCfg, Layers: []ocispec.Descriptor{chartLayer}}
	chart.SchemaVersion = 2
	f.Chart = r.PushManifest(f.ChartRepo, "0.1.0", ocispec.MediaTypeImageManifest, chart)

	return f
}

// PushArtifact pushes an OCI 1.1 artifact manifest with an empty config and a
// single layer that refers to subject.
func PushArtifact(r *Registry, repo string, subject ocispec.Descriptor, artifactType string, annotations map[string]string, layerType, layerContent string) ocispec.Descriptor {
	empty := r.PushBlob(repo, ocispec.MediaTypeEmptyJSON, []byte("{}"))
	layer := r.PushBlob(repo, layerType, []byte(layerContent))
	subj := ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	m := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       empty,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subj,
		Annotations:  annotations,
	}
	m.SchemaVersion = 2
	d := r.PushManifest(repo, "", ocispec.MediaTypeImageManifest, m)
	d.ArtifactType = artifactType
	d.Annotations = annotations
	return d
}

// DigestTag returns the tag form (sha256-<hex>) of a digest.
func DigestTag(d digest.Digest) string {
	return strings.Replace(d.String(), ":", "-", 1)
}
