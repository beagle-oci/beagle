package ui

import (
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/oci/ocitest"
	"github.com/beagle-oci/beagle/internal/sigverify"
	"github.com/beagle-oci/beagle/internal/sigverify/sigtest"
)

const (
	signedRepo = "signed/app"
	alice      = "alice@example.com"
	issuer     = "https://issuer.example"
	bundleType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

func newSigstore(t *testing.T) *sigtest.Sigstore {
	t.Helper()
	s, err := sigtest.New()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// must fails the test on error: must(t)(f()).
func must(t *testing.T) func([]byte, error) []byte {
	return func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

// signedRegistry adds signed/app with images signed in different ways:
// good (cosign v3 bundle), legacy (cosign .sig tag), bad (signed by another
// Sigstore instance), notation and unsigned.
func signedRegistry(t *testing.T) (*ocitest.Registry, *sigtest.Sigstore) {
	t.Helper()
	r := ocitest.New()
	ocitest.Seed(r)
	s, other := newSigstore(t), newSigstore(t)

	image := func(tag string) ocispec.Descriptor {
		cfg := r.PushBlob(signedRepo, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`))
		layer := r.PushBlob(signedRepo, ocispec.MediaTypeImageLayerGzip, []byte("layer-"+tag))
		m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: []ocispec.Descriptor{layer}}
		m.SchemaVersion = 2
		return r.PushManifest(signedRepo, tag, ocispec.MediaTypeImageManifest, m)
	}
	bundleAnn := map[string]string{
		oci.AnnotationSigstoreContent:       "dsse-envelope",
		oci.AnnotationSigstorePredicateType: oci.PredicateCosignSign,
	}

	good := image("good")
	ocitest.PushArtifact(r, signedRepo, good, bundleType, bundleAnn, bundleType, string(must(t)(s.SignImage(good.Digest, alice, issuer))))

	bad := image("bad")
	ocitest.PushArtifact(r, signedRepo, bad, bundleType, bundleAnn, bundleType, string(must(t)(other.SignImage(bad.Digest, alice, issuer))))

	legacy := image("legacy")
	payload, ann, err := s.SignLegacy(legacy.Digest, alice, issuer)
	if err != nil {
		t.Fatal(err)
	}
	layer := r.PushBlob(signedRepo, sigverify.MediaTypeSimpleSigning, payload)
	layer.Annotations = ann
	cfg := r.PushBlob(signedRepo, ocispec.MediaTypeImageConfig, []byte(`{}`))
	sig := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: []ocispec.Descriptor{layer}}
	sig.SchemaVersion = 2
	r.PushManifest(signedRepo, strings.Replace(legacy.Digest.String(), ":", "-", 1)+".sig", ocispec.MediaTypeImageManifest, sig)

	notation := image("notation")
	ocitest.PushArtifact(r, signedRepo, notation, "application/vnd.cncf.notary.signature", nil, "application/jose+json", `{"payload":"x"}`)

	image("unsigned")
	return r, s
}

func TestSignatureVerificationInTagList(t *testing.T) {
	r, s := signedRegistry(t)
	h := newHarness(t, r, Options{Repository: signedRepo, Verifier: sigverify.New(s.Material())})

	screen := h.expect("tags", "Signatures:", "verified via custom trusted root")
	for tag, want := range map[string]string{
		"good":     "✓ cosign",
		"legacy":   "✓ cosign",
		"bad":      "✗ cosign",
		"notation": "? notation",
	} {
		if r := row(t, screen, "│ "+tag+" "); !strings.Contains(r, want) {
			t.Errorf("row %q lacks %q", r, want)
		}
	}
	if r := row(t, screen, "│ unsigned "); strings.ContainsAny(r, "✓✗?•") {
		t.Errorf("unsigned row shows a signature: %q", r)
	}
}

func TestSignatureVerificationInManifestView(t *testing.T) {
	r, s := signedRegistry(t)
	opts := Options{Repository: signedRepo, Verifier: sigverify.New(s.Material())}

	for _, c := range []struct {
		ref  string
		want []string
	}{
		{"good", []string{"Signatures:", "✓ verified (cosign)", "Signed by:", alice, issuer, "Logged:", "log index"}},
		{"legacy", []string{"Signatures:", "✓ verified (cosign)", alice}},
		{"bad", []string{"Signatures:", "✗ invalid:"}},
		{"notation", []string{"Signatures:", "? not verified: notation signatures are not verified yet"}},
		{"unsigned", []string{"Signatures:", "none"}},
	} {
		t.Run(c.ref, func(t *testing.T) {
			opts.Reference = c.ref
			h := newHarness(t, r, opts)
			h.expect(c.ref, c.want...)
		})
	}

	// From the referrer tree into the signature itself.
	opts.Reference = "good"
	h := newHarness(t, r, opts)
	h.key("r")
	h.expect("referrers", "referrers(signed/app:good)", "signature")
	h.key("down", "enter")
	h.expect("signature", "Verification:", "✓ verified (cosign)", alice)

	// The cosign legacy tag knows its subject from its name.
	h.key("esc", "esc", "esc")
	screen := h.expect("tags", "tags(signed/app)")
	sigTag := ""
	for _, line := range strings.Split(screen, "\n") {
		if strings.Contains(line, ".sig") {
			sigTag = line
		}
	}
	if sigTag == "" {
		t.Fatalf("no legacy signature tag:\n%s", screen)
	}
}

func TestVerificationOfLegacyTagAndNotation(t *testing.T) {
	r, s := signedRegistry(t)
	v := sigverify.New(s.Material())

	// Find the digests via the tag list of a harness without verification.
	h := newHarness(t, r, Options{Repository: signedRepo})
	screen := h.expect("tags", "not verified (--no-verify)", "• cosign")
	if strings.ContainsAny(row(t, screen, "│ good "), "✓✗") {
		t.Fatal("without a verifier nothing is verified")
	}

	// Open the legacy .sig manifest by tag: its name tells the subject.
	legacy := r.Resolve(t, signedRepo, "legacy")
	sigTag := strings.Replace(legacy.String(), ":", "-", 1) + ".sig"
	h = newHarness(t, r, Options{Repository: signedRepo, Reference: sigTag, Verifier: v})
	h.expect("legacy-sig", "Verification:", "✓ verified (cosign)", alice)

	// A notation signature is shown as not verifiable.
	notation := r.Resolve(t, signedRepo, "notation")
	h = newHarness(t, r, Options{Repository: signedRepo, Reference: "notation", Verifier: v})
	h.key("r")
	h.expect("notation-referrers", "notary")
	h.key("down", "enter")
	h.expect("notation-sig", "Verification:", "? not verified: notation", notation.Encoded()[:12])
}

func TestAttestationVerification(t *testing.T) {
	r, s := signedRegistry(t)
	good := r.Resolve(t, signedRepo, "good")
	att := must(t)(s.Attest(good, "https://slsa.dev/provenance/v1", alice, issuer))
	d := ocitest.PushArtifact(r, signedRepo, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: good}, bundleType,
		map[string]string{oci.AnnotationSigstoreContent: "dsse-envelope", oci.AnnotationSigstorePredicateType: "https://slsa.dev/provenance/v1"},
		bundleType, string(att))

	h := newHarness(t, r, Options{Repository: signedRepo, Reference: d.Digest.String(), Verifier: sigverify.New(s.Material())})
	h.expect("attestation", "Kind:", "attestation", "Verification:", "✓ verified (cosign, https://slsa.dev/provenance/v1)")

	// The attestation is no signature: the tag stays verified by its real one.
	h = newHarness(t, r, Options{Repository: signedRepo, Verifier: sigverify.New(s.Material())})
	if row := row(t, h.expect("tags", "good"), "│ good "); !strings.Contains(row, "✓ cosign") || !strings.Contains(row, "att") {
		t.Fatalf("good row = %q", row)
	}
}

func TestVerificationFields(t *testing.T) {
	var none *verification
	if none.fields() != nil {
		t.Error("nil verification should render nothing")
	}
	loading := &verification{label: "Signatures", state: stateLoading}
	if f := loading.fields(); len(f) != 1 || f[0].value != "… verifying" {
		t.Errorf("loading = %+v", f)
	}
	ci := &verification{label: "Signatures", state: stateDone, result: sigverify.Result{
		Status: sigverify.Verified, Format: oci.FormatCosign, LogIndex: -1,
		Signer:           "https://github.com/beagle-oci/beagle/.github/workflows/release.yml@refs/tags/v1.0.0",
		Issuer:           "https://token.actions.githubusercontent.com",
		SourceRepository: "https://github.com/beagle-oci/beagle",
		SourceRevision:   "0123456789abcdef0123",
	}}
	got := ci.fields()
	if len(got) != 3 || got[2].label != "Source" || got[2].value != "https://github.com/beagle-oci/beagle @ 0123456789ab" {
		t.Errorf("CI identity = %+v", got)
	}
}

func TestSignatureVerificationInReferrerTree(t *testing.T) {
	r, s := signedRegistry(t)
	opts := Options{Repository: signedRepo, Verifier: sigverify.New(s.Material())}

	for ref, want := range map[string]string{"good": "✓", "legacy": "✓", "bad": "✗", "notation": "?"} {
		t.Run(ref, func(t *testing.T) {
			opts.Reference = ref
			h := newHarness(t, r, opts)
			h.key("r")
			screen := h.expect("referrers", "VERIFIED", "signature")
			line := row(t, screen, " signature ")
			if !strings.Contains(line, " "+want+" ") {
				t.Fatalf("signature row %q lacks %q", line, want)
			}
		})
	}

	// Without verification there is no VERIFIED column.
	opts.Verifier, opts.Reference = nil, "good"
	h := newHarness(t, r, opts)
	h.key("r")
	if screen := h.expect("referrers-off", "signature"); strings.Contains(screen, "VERIFIED") {
		t.Fatalf("VERIFIED column without verification:\n%s", screen)
	}
}
