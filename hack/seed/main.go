// Command seed pushes demo content to a registry so beagle has something to
// show during development: a multi-platform image with signatures, an SBOM,
// attestations, scan results, cosign legacy tags, Helm charts and a generic
// artifact.
//
// Usage:
//
//	go run ./hack/seed localhost:5050
//	go run ./hack/seed --plain-http=false registry.example.com
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

func main() {
	plainHTTP := flag.Bool("plain-http", true, "use HTTP instead of HTTPS")
	prefix := flag.String("prefix", "demo", "repository namespace")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: seed [flags] <registry>")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	s := &seeder{host: flag.Arg(0), plainHTTP: *plainHTTP, prefix: *prefix}
	if err := s.run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

type seeder struct {
	host      string
	plainHTTP bool
	prefix    string
	client    *auth.Client
}

func (s *seeder) repo(name string) (*remote.Repository, error) {
	if s.client == nil {
		s.client = &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
		if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
			s.client.Credential = credentials.Credential(store)
		}
	}
	r, err := remote.NewRepository(s.host + "/" + s.prefix + "/" + name)
	if err != nil {
		return nil, err
	}
	r.PlainHTTP = s.plainHTTP
	r.Client = s.client
	// Keep stale referrers tag indexes instead of deleting them, so seeding
	// works on registries without the delete API.
	r.SkipReferrersGC = true
	return r, nil
}

func (s *seeder) run(ctx context.Context) error {
	app, err := s.repo("app")
	if err != nil {
		return err
	}

	amd64, err := pushImage(ctx, app, "amd64", "v1.0.0")
	if err != nil {
		return err
	}
	arm64, err := pushImage(ctx, app, "arm64", "v1.0.0")
	if err != nil {
		return err
	}
	index, err := pushIndex(ctx, app, amd64, arm64)
	if err != nil {
		return err
	}
	for _, tag := range []string{"v1.0.0", "latest"} {
		if err := app.Tag(ctx, index, tag); err != nil {
			return err
		}
	}
	old, err := pushImage(ctx, app, "amd64", "v0.9.0")
	if err != nil {
		return err
	}
	if err := app.Tag(ctx, old, "v0.9.0"); err != nil {
		return err
	}
	log.Printf("pushed %s/%s/app:v1.0.0 (%s)", s.host, s.prefix, index.Digest)

	bundle := "application/vnd.dev.sigstore.bundle.v0.3+json"
	sig, err := attach(ctx, app, index, bundle, map[string]string{"dev.sigstore.bundle.content": "message-signature"},
		bundle, `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","messageSignature":{"signature":"MEUCIQ..."}}`)
	if err != nil {
		return err
	}
	sbom, err := attach(ctx, app, index, "application/spdx+json", nil, "application/spdx+json", spdxDocument())
	if err != nil {
		return err
	}
	if _, err := attach(ctx, app, sbom, bundle, map[string]string{"dev.sigstore.bundle.content": "message-signature"},
		bundle, `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","messageSignature":{"signature":"MEYCIQ..."}}`); err != nil {
		return err
	}
	if _, err := attach(ctx, app, index, bundle, map[string]string{
		"dev.sigstore.bundle.content":       "dsse-envelope",
		"dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1",
	}, bundle, `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":{"payloadType":"application/vnd.in-toto+json"}}`); err != nil {
		return err
	}
	if _, err := attach(ctx, app, index, "application/vnd.openvex+json", nil, "application/vnd.openvex+json",
		`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`); err != nil {
		return err
	}
	if _, err := attach(ctx, app, amd64, "application/vnd.cncf.notary.signature",
		map[string]string{"io.cncf.notary.x509chain.thumbprint#S256": `["b7e1a5..."]`}, "application/jose+json", `{"payload":"eyJ0YXJnZXRBcnRpZmFjdCI6e319"}`); err != nil {
		return err
	}
	if _, err := attach(ctx, app, arm64, "application/sarif+json", nil, "application/sarif+json",
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},"results":[]}]}`); err != nil {
		return err
	}
	log.Printf("attached signature %s, SBOM %s and more", sig.Digest, sbom.Digest)

	// cosign < v3 stored signatures and attestations under digest tags.
	digestTag := strings.Replace(index.Digest.String(), ":", "-", 1)
	if err := pushLegacyCosign(ctx, app, digestTag+".sig", "application/vnd.dev.cosign.simplesigning.v1+json",
		fmt.Sprintf(`{"critical":{"identity":{"docker-reference":"%s/%s/app"},"image":{"docker-manifest-digest":"%s"},"type":"cosign container image signature"}}`, s.host, s.prefix, index.Digest)); err != nil {
		return err
	}
	if err := pushLegacyCosign(ctx, app, digestTag+".att", "application/vnd.dsse.envelope.v1+json",
		`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`); err != nil {
		return err
	}
	log.Printf("pushed cosign legacy tags %s.sig and .att", digestTag)

	chart, err := s.repo("chart")
	if err != nil {
		return err
	}
	for _, v := range []string{"0.1.0", "0.2.0"} {
		if err := pushChart(ctx, chart, v); err != nil {
			return err
		}
	}
	log.Printf("pushed %s/%s/chart:0.1.0 and 0.2.0", s.host, s.prefix)

	docs, err := s.repo("docs")
	if err != nil {
		return err
	}
	layer, err := pushBlob(ctx, docs, "text/markdown", []byte("# beagle\n\nSniffing around registries.\n"), "README.md")
	if err != nil {
		return err
	}
	d, err := oras.PackManifest(ctx, docs, oras.PackManifestVersion1_1, "application/vnd.example.docs.v1", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		return err
	}
	if err := docs.Tag(ctx, d, "latest"); err != nil {
		return err
	}
	log.Printf("pushed %s/%s/docs:latest", s.host, s.prefix)
	return nil
}

func pushBlob(ctx context.Context, r *remote.Repository, mediaType string, data []byte, title string) (ocispec.Descriptor, error) {
	d, err := oras.PushBytes(ctx, r, mediaType, data)
	if err != nil {
		return d, err
	}
	if title != "" {
		d.Annotations = map[string]string{ocispec.AnnotationTitle: title}
	}
	return d, nil
}

func pushImage(ctx context.Context, r *remote.Repository, arch, version string) (ocispec.Descriptor, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("#!/bin/sh\necho hello from " + arch + " " + version + "\n")
	_ = tw.WriteHeader(&tar.Header{Name: "app", Mode: 0o755, Size: int64(len(content)), ModTime: time.Unix(0, 0)})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	layer, err := pushBlob(ctx, r, ocispec.MediaTypeImageLayerGzip, buf.Bytes(), "")
	if err != nil {
		return layer, err
	}

	created := time.Now().UTC()
	cfg, _ := json.Marshal(ocispec.Image{
		Created:  &created,
		Platform: ocispec.Platform{OS: "linux", Architecture: arch},
		Config: ocispec.ImageConfig{
			Entrypoint: []string{"/app"},
			Env:        []string{"PATH=/usr/local/bin:/usr/bin:/bin"},
			Labels:     map[string]string{"org.opencontainers.image.version": version},
		},
		RootFS:  ocispec.RootFS{Type: "layers"},
		History: []ocispec.History{{Created: &created, CreatedBy: "COPY app /app"}},
	})
	config, err := pushBlob(ctx, r, ocispec.MediaTypeImageConfig, cfg, "")
	if err != nil {
		return config, err
	}
	d, err := oras.PackManifest(ctx, r, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           []ocispec.Descriptor{layer},
		ManifestAnnotations: map[string]string{
			ocispec.AnnotationCreated: created.Format(time.RFC3339),
			ocispec.AnnotationVersion: version,
			ocispec.AnnotationSource:  "https://github.com/example/app",
		},
	})
	if err != nil {
		return d, err
	}
	d.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}
	return d, nil
}

func pushIndex(ctx context.Context, r *remote.Repository, manifests ...ocispec.Descriptor) (ocispec.Descriptor, error) {
	idx := ocispec.Index{
		MediaType:   ocispec.MediaTypeImageIndex,
		Manifests:   manifests,
		Annotations: map[string]string{ocispec.AnnotationCreated: time.Now().UTC().Format(time.RFC3339)},
	}
	idx.SchemaVersion = 2
	data, err := json.Marshal(idx)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return oras.PushBytes(ctx, r, ocispec.MediaTypeImageIndex, data)
}

// attach pushes an OCI 1.1 artifact that refers to subject. oras-go
// maintains the referrers tag schema if the registry lacks the referrers API.
func attach(ctx context.Context, r *remote.Repository, subject ocispec.Descriptor, artifactType string, annotations map[string]string, layerType, content string) (ocispec.Descriptor, error) {
	layer, err := pushBlob(ctx, r, layerType, []byte(content), "")
	if err != nil {
		return layer, err
	}
	subj := ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	return oras.PackManifest(ctx, r, oras.PackManifestVersion1_1, artifactType, oras.PackManifestOptions{
		Subject:             &subj,
		Layers:              []ocispec.Descriptor{layer},
		ManifestAnnotations: annotations,
	})
}

func pushLegacyCosign(ctx context.Context, r *remote.Repository, tag, layerType, payload string) error {
	layer, err := pushBlob(ctx, r, layerType, []byte(payload), "")
	if err != nil {
		return err
	}
	config, err := pushBlob(ctx, r, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"","os":"","rootfs":{"type":"layers","diff_ids":[]}}`), "")
	if err != nil {
		return err
	}
	d, err := oras.PackManifest(ctx, r, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           []ocispec.Descriptor{layer},
	})
	if err != nil {
		return err
	}
	return r.Tag(ctx, d, tag)
}

func pushChart(ctx context.Context, r *remote.Repository, version string) error {
	cfg := fmt.Sprintf(`{"name":"demo","version":"%s","apiVersion":"v2","description":"A demo chart"}`, version)
	config, err := pushBlob(ctx, r, "application/vnd.cncf.helm.config.v1+json", []byte(cfg), "")
	if err != nil {
		return err
	}
	layer, err := pushBlob(ctx, r, "application/vnd.cncf.helm.chart.content.v1.tar+gzip", []byte("not really a chart "+version), "demo-"+version+".tgz")
	if err != nil {
		return err
	}
	d, err := oras.PackManifest(ctx, r, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           []ocispec.Descriptor{layer},
	})
	if err != nil {
		return err
	}
	return r.Tag(ctx, d, version)
}

func spdxDocument() string {
	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "demo/app",
		"documentNamespace": "https://example.com/spdx/demo-app",
		"creationInfo":      map[string]any{"created": time.Now().UTC().Format(time.RFC3339), "creators": []string{"Tool: seed"}},
		"packages": []map[string]any{
			{"name": "busybox", "SPDXID": "SPDXRef-busybox", "versionInfo": "1.36.1", "downloadLocation": "NOASSERTION"},
			{"name": "musl", "SPDXID": "SPDXRef-musl", "versionInfo": "1.2.5", "downloadLocation": "NOASSERTION"},
		},
	}
	data, _ := json.Marshal(doc)
	return string(data)
}
