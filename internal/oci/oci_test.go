package oci_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
)

func newClient(t *testing.T, r *ocitest.Registry) *oci.Client {
	t.Helper()
	host := r.Start(t)
	c, err := oci.New(host, oci.Options{
		PlainHTTP:  true,
		Credential: func(context.Context, string) (auth.Credential, error) { return auth.EmptyCredential, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBrowse(t *testing.T) {
	r := ocitest.New()
	f := ocitest.Seed(r)
	c := newClient(t, r)
	ctx := context.Background()

	repos, err := c.Repositories(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(repos, ",") != "demo/app,demo/chart" {
		t.Fatalf("repositories = %v", repos)
	}

	tags, err := c.Tags(ctx, f.Repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 {
		t.Fatalf("tags = %v", tags)
	}

	desc, err := c.Resolve(ctx, f.Repo, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != f.Index.Digest {
		t.Fatalf("resolved %s, want %s", desc.Digest, f.Index.Digest)
	}

	m, err := c.FetchManifest(ctx, f.Repo, desc)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsIndex() || len(m.Manifests) != 2 {
		t.Fatalf("expected index with 2 manifests, got %+v", m)
	}
	if got := oci.ClassifyManifest(m); got != oci.KindIndex {
		t.Fatalf("index classified as %s", got)
	}

	img, err := c.FetchManifestReference(ctx, f.Repo, f.AMD64.Digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if img.IsIndex() || img.Config == nil || len(img.Layers) != 1 {
		t.Fatalf("unexpected image manifest %+v", img)
	}

	cfg, err := c.FetchBlob(ctx, f.Repo, *img.Config, oci.DefaultMaxBlobSize)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `"amd64"`) {
		t.Fatalf("config = %s", cfg)
	}
	if _, err := c.FetchBlob(ctx, f.Repo, *img.Config, 1); !errors.Is(err, oci.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}

	chart, err := c.FetchManifestReference(ctx, f.ChartRepo, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := oci.ClassifyManifest(chart); got != oci.KindHelmChart {
		t.Fatalf("chart classified as %s", got)
	}
}

func TestCatalogUnavailable(t *testing.T) {
	r := ocitest.New()
	r.Catalog = false
	ocitest.Seed(r)
	c := newClient(t, r)
	_, err := c.Repositories(context.Background(), 0)
	if !errors.Is(err, oci.ErrCatalogUnavailable) {
		t.Fatalf("expected ErrCatalogUnavailable, got %v", err)
	}
}

func TestReferrerTree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		api    bool
		status int
	}{
		{"referrers-api", true, 0},
		{"tag-fallback-404", false, http.StatusNotFound},
		{"tag-fallback-405", false, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ocitest.New()
			r.ReferrersAPI = tc.api
			r.ReferrersDisabledStatus = tc.status
			f := ocitest.Seed(r)
			c := newClient(t, r)

			tree, err := c.ReferrerTree(context.Background(), f.Repo, f.Index, oci.TreeOptions{})
			if err != nil {
				t.Fatal(err)
			}

			byDigest := map[digest.Digest]*oci.TreeNode{}
			for _, fn := range tree.Flatten() {
				if fn.Node.Err != nil {
					t.Errorf("node %s: %v", fn.Node.Descriptor.Digest, fn.Node.Err)
				}
				byDigest[fn.Node.Descriptor.Digest] = fn.Node
			}

			want := map[digest.Digest]oci.Kind{
				f.Signature.Digest:  oci.KindSignature,
				f.SBOM.Digest:       oci.KindSBOM,
				f.SBOMSig.Digest:    oci.KindSignature,
				f.Provenance.Digest: oci.KindAttestation,
				f.Notation.Digest:   oci.KindSignature,
				f.CosignSig.Digest:  oci.KindSignature,
				f.AMD64.Digest:      oci.KindImage,
				f.ARM64.Digest:      oci.KindImage,
			}
			for d, kind := range want {
				n, ok := byDigest[d]
				if !ok {
					t.Errorf("missing node %s (%s)", d, kind)
					continue
				}
				if n.Kind != kind {
					t.Errorf("node %s: kind %s, want %s", d, n.Kind, kind)
				}
			}

			if n := byDigest[f.CosignSig.Digest]; n != nil && (n.Source != oci.SourceCosignTag || n.Label != f.CosignTag) {
				t.Errorf("cosign tag node = %+v", n)
			}
			if n := byDigest[f.SBOM.Digest]; n != nil && (len(n.Children) != 1 || n.Children[0].Descriptor.Digest != f.SBOMSig.Digest) {
				t.Errorf("SBOM signature not nested under SBOM: %+v", n.Children)
			}
			if n := byDigest[f.AMD64.Digest]; n != nil && (n.Label != "linux/amd64" || len(n.Children) != 1) {
				t.Errorf("amd64 platform node = %+v", n)
			}
			if got, want := tree.Count(), len(want); got != want {
				t.Errorf("tree has %d nodes, want %d", got, want)
			}
		})
	}
}

func TestFlattenPrefixes(t *testing.T) {
	leaf := func() *oci.TreeNode { return &oci.TreeNode{} }
	root := &oci.TreeNode{Children: []*oci.TreeNode{
		{Children: []*oci.TreeNode{leaf(), leaf()}},
		leaf(),
	}}
	var got []string
	for _, n := range root.Flatten() {
		got = append(got, n.Prefix)
	}
	want := []string{"", "├─ ", "│  ├─ ", "│  └─ ", "└─ "}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("prefixes = %q, want %q", got, want)
	}
}

func TestParseSubjectTag(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	tests := []struct {
		tag    string
		ok     bool
		kind   oci.Kind
		scheme string
	}{
		{"sha256-" + hex + ".sig", true, oci.KindSignature, oci.SchemeCosign},
		{"sha256-" + hex + ".att", true, oci.KindAttestation, oci.SchemeCosign},
		{"sha256-" + hex + ".sbom", true, oci.KindSBOM, oci.SchemeCosign},
		{"sha256-" + hex, true, oci.KindReferrersIndex, oci.SchemeReferrersTag},
		{"sha256-" + hex + ".foo", false, 0, ""},
		{"sha256-abc.sig", false, 0, ""},
		{"md5-" + hex + ".sig", false, 0, ""},
		{"v1.0.0", false, 0, ""},
	}
	for _, tt := range tests {
		st, ok := oci.ParseSubjectTag(tt.tag)
		if ok != tt.ok {
			t.Errorf("%s: ok = %v, want %v", tt.tag, ok, tt.ok)
			continue
		}
		if ok && (st.Kind != tt.kind || st.Scheme != tt.scheme || st.Subject.Encoded() != hex) {
			t.Errorf("%s: got %+v", tt.tag, st)
		}
	}
}

func TestClassifyDescriptor(t *testing.T) {
	tests := []struct {
		name string
		desc ocispec.Descriptor
		want oci.Kind
	}{
		{"notation", ocispec.Descriptor{ArtifactType: "application/vnd.cncf.notary.signature"}, oci.KindSignature},
		{"cosign bundle signature", ocispec.Descriptor{ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json"}, oci.KindSignature},
		{"cosign bundle attestation", ocispec.Descriptor{
			ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
			Annotations:  map[string]string{oci.AnnotationSigstorePredicateType: "https://slsa.dev/provenance/v1"},
		}, oci.KindAttestation},
		{"spdx", ocispec.Descriptor{ArtifactType: "application/spdx+json"}, oci.KindSBOM},
		{"cyclonedx", ocispec.Descriptor{ArtifactType: "application/vnd.cyclonedx+json"}, oci.KindSBOM},
		{"in-toto", ocispec.Descriptor{ArtifactType: "application/vnd.in-toto+json"}, oci.KindAttestation},
		{"sarif", ocispec.Descriptor{ArtifactType: "application/sarif+json"}, oci.KindVulnReport},
		{"openvex", ocispec.Descriptor{ArtifactType: "application/openvex+json"}, oci.KindVEX},
		{"unknown artifact", ocispec.Descriptor{ArtifactType: "application/x-custom"}, oci.KindArtifact},
		{"index", ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, oci.KindIndex},
		{"image", ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, oci.KindImage},
		{"buildx attestation", ocispec.Descriptor{
			MediaType:   ocispec.MediaTypeImageManifest,
			Annotations: map[string]string{oci.AnnotationDockerReferenceType: "attestation-manifest"},
		}, oci.KindAttestation},
	}
	for _, tt := range tests {
		if got := oci.ClassifyDescriptor(tt.desc); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestHostHelpers(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost:5000": true, "127.0.0.1:5000": true, "[::1]:5000": true,
		"registry.localhost": true, "ghcr.io": false, "10.0.0.1:5000": false,
	} {
		if got := oci.IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}

	hub, err := oci.New("docker.io", oci.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hub.NormalizeRepository("nginx"); got != "library/nginx" {
		t.Errorf("NormalizeRepository(nginx) = %q", got)
	}
	if got := hub.NormalizeRepository("bitnami/nginx"); got != "bitnami/nginx" {
		t.Errorf("NormalizeRepository(bitnami/nginx) = %q", got)
	}
}

func TestAttachmentsAndCreated(t *testing.T) {
	for _, api := range []bool{true, false} {
		r := ocitest.New()
		r.ReferrersAPI = api
		f := ocitest.Seed(r)
		c := newClient(t, r)
		ctx := context.Background()
		tags, err := c.Tags(ctx, f.Repo)
		if err != nil {
			t.Fatal(err)
		}

		a, err := c.Attachments(ctx, f.Repo, f.Index, tags)
		if err != nil {
			t.Fatal(err)
		}
		// sigstore bundle signature + cosign legacy .sig tag -> "cosign";
		// SBOM and SLSA provenance are attached as well.
		if strings.Join(a.Signatures, ",") != "cosign" || a.Kinds[oci.KindSBOM] != 1 || a.Kinds[oci.KindAttestation] != 1 {
			t.Errorf("index attachments (api=%v) = %+v", api, a)
		}

		amd, err := c.Attachments(ctx, f.Repo, f.AMD64, tags)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(amd.Signatures, ",") != "notation" {
			t.Errorf("amd64 signatures = %v", amd.Signatures)
		}

		arm, err := c.Attachments(ctx, f.Repo, f.ARM64, tags)
		if err != nil {
			t.Fatal(err)
		}
		if arm.Signed() {
			t.Errorf("arm64 should be unsigned: %+v", arm)
		}

		idx, err := c.FetchManifest(ctx, f.Repo, f.Index)
		if err != nil {
			t.Fatal(err)
		}
		created, err := c.Created(ctx, f.Repo, idx)
		if err != nil {
			t.Fatal(err)
		}
		if !created.Equal(ocitest.Created) {
			t.Errorf("created = %v, want %v", created, ocitest.Created)
		}

		chart, err := c.FetchManifestReference(ctx, f.ChartRepo, "0.1.0")
		if err != nil {
			t.Fatal(err)
		}
		if created, _ := c.Created(ctx, f.ChartRepo, chart); !created.IsZero() {
			t.Errorf("chart has no build time, got %v", created)
		}
	}
}
