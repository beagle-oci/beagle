package sigverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/sigverify/sigtest"
)

const (
	alice  = "alice@example.com"
	issuer = "https://issuer.example"
)

func newSigstore(t *testing.T) *sigtest.Sigstore {
	t.Helper()
	s, err := sigtest.New()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

var subject = digest.FromString("the image manifest")

func TestVerifyBundleImageSignature(t *testing.T) {
	s := newSigstore(t)
	b := must[[]byte](t)(s.SignImage(subject, alice, issuer))
	v := New(s.Material())

	r := v.VerifyBundle(b, subject)
	if r.Status != Verified {
		t.Fatalf("status %v: %s", r.Status, r.Reason)
	}
	if r.Signer != alice || r.Issuer != issuer {
		t.Errorf("signer %q issuer %q", r.Signer, r.Issuer)
	}
	if r.PredicateType != oci.PredicateCosignSign || r.Format != oci.FormatCosign {
		t.Errorf("predicate %q format %q", r.PredicateType, r.Format)
	}
	if r.Time.IsZero() || r.LogIndex < 0 {
		t.Errorf("time %v log index %d", r.Time, r.LogIndex)
	}

	if r := v.VerifyBundle(b, digest.FromString("another image")); r.Status != Invalid {
		t.Errorf("other subject: %v", r.Status)
	}
	if r := New(newSigstore(t).Material()).VerifyBundle(b, subject); r.Status != Invalid {
		t.Errorf("other Sigstore instance: %v", r.Status)
	}
	if r := v.VerifyBundle([]byte("{"), subject); r.Status != Invalid || !strings.Contains(r.Reason, "cannot parse bundle") {
		t.Errorf("malformed bundle: %v %q", r.Status, r.Reason)
	}
	if r := v.VerifyBundle(b, digest.Digest("sha256:nothex")); r.Status != Invalid {
		t.Errorf("invalid subject digest: %v", r.Status)
	}
}

func TestVerifyBundleTampered(t *testing.T) {
	s := newSigstore(t)
	b := must[[]byte](t)(s.SignImage(subject, alice, issuer))
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	env := doc["dsseEnvelope"].(map[string]any)
	sig := env["signatures"].([]any)[0].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(sig["sig"].(string))
	raw[len(raw)-1] ^= 0xff
	sig["sig"] = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := json.Marshal(doc)

	if r := New(s.Material()).VerifyBundle(tampered, subject); r.Status != Invalid {
		t.Fatalf("tampered signature: %v", r.Status)
	}
}

func TestVerifyBundleSignedWithKey(t *testing.T) {
	s := newSigstore(t)
	b := must[[]byte](t)(s.SignImage(subject, alice, issuer))
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	vm := doc["verificationMaterial"].(map[string]any)
	delete(vm, "certificate")
	vm["publicKey"] = map[string]any{"hint": "a-key"}
	keyed, _ := json.Marshal(doc)

	r := New(s.Material()).VerifyBundle(keyed, subject)
	if r.Status != Unverified || !strings.Contains(r.Reason, "key") {
		t.Fatalf("key-signed bundle: %v %q", r.Status, r.Reason)
	}
}

func TestVerifyBundleAttestationAndMessage(t *testing.T) {
	s := newSigstore(t)
	v := New(s.Material())

	att := must[[]byte](t)(s.Attest(subject, "https://slsa.dev/provenance/v1", alice, issuer))
	if r := v.VerifyBundle(att, subject); r.Status != Verified || r.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("attestation: %v %q %s", r.Status, r.PredicateType, r.Reason)
	}

	manifest := []byte(`{"schemaVersion":2}`)
	msg := must[[]byte](t)(s.SignMessage(manifest, alice, issuer))
	if r := v.VerifyBundle(msg, digest.FromBytes(manifest)); r.Status != Verified || r.PredicateType != "" {
		t.Fatalf("message signature: %v %s", r.Status, r.Reason)
	}
	if r := v.VerifyBundle(msg, subject); r.Status != Invalid {
		t.Fatalf("message signature over another digest: %v", r.Status)
	}
}

func TestVerifyLegacy(t *testing.T) {
	s := newSigstore(t)
	v := New(s.Material())
	payload, ann, err := s.SignLegacy(subject, alice, issuer)
	if err != nil {
		t.Fatal(err)
	}

	r := v.VerifyLegacy(payload, ann, subject)
	if r.Status != Verified || r.Signer != alice || r.LogIndex < 0 {
		t.Fatalf("legacy signature: %+v", r)
	}

	with := func(key, value string) map[string]string {
		out := map[string]string{}
		for k, v := range ann {
			out[k] = v
		}
		if value == "" {
			delete(out, key)
		} else {
			out[key] = value
		}
		return out
	}
	for name, c := range map[string]struct {
		payload []byte
		ann     map[string]string
		subject digest.Digest
		want    Status
		reason  string
	}{
		"other subject":     {payload, ann, digest.FromString("other"), Invalid, "signature is for"},
		"malformed payload": {[]byte("{"), ann, subject, Invalid, "payload"},
		"no signature":      {payload, with(annotationSignature, ""), subject, Invalid, "signature annotation"},
		"bad signature":     {payload, with(annotationSignature, "!!"), subject, Invalid, "signature annotation"},
		"signed with key":   {payload, with(annotationCertificate, ""), subject, Unverified, "key"},
		"bad certificate":   {payload, with(annotationCertificate, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), subject, Invalid, "certificate"},
		"not a certificate": {payload, with(annotationCertificate, "garbage"), subject, Invalid, "certificate"},
		"no log entry":      {payload, with(annotationBundle, ""), subject, Invalid, "transparency log"},
		"bad log entry":     {payload, with(annotationBundle, "{"), subject, Invalid, "log entry"},
		"bad log body":      {payload, with(annotationBundle, `{"Payload":{"body":"!!"}}`), subject, Invalid, "body"},
		"bad log ID":        {payload, with(annotationBundle, `{"Payload":{"body":"e30=","logID":"zz"}}`), subject, Invalid, "log ID"},
		"log body not JSON": {payload, with(annotationBundle, `{"Payload":{"body":"eA==","logID":"00"}}`), subject, Invalid, "body"},
		"forged log entry":  {payload, with(annotationBundle, `{"Payload":{"body":"e30=","logID":"00"}}`), subject, Invalid, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := v.VerifyLegacy(c.payload, c.ann, c.subject)
			if r.Status != c.want || !strings.Contains(r.Reason, c.reason) {
				t.Fatalf("got %v %q, want %v containing %q", r.Status, r.Reason, c.want, c.reason)
			}
		})
	}
}

func TestTrustedRootUnavailable(t *testing.T) {
	s := newSigstore(t)
	b := must[[]byte](t)(s.SignImage(subject, alice, issuer))
	calls := 0
	now := time.Now()
	v := newVerifier("test", func() (root.TrustedMaterial, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("offline")
		}
		return s.Material(), nil
	})
	v.now = func() time.Time { return now }

	if r := v.VerifyBundle(b, subject); r.Status != Unverified || !strings.Contains(r.Reason, "trusted root unavailable: offline") {
		t.Fatalf("first attempt: %v %q", r.Status, r.Reason)
	}
	if r := v.VerifyBundle(b, subject); r.Status != Unverified || calls != 1 {
		t.Fatalf("the failure should be cached: %v, %d loads", r.Status, calls)
	}
	now = now.Add(errorRetry)
	if r := v.VerifyBundle(b, subject); r.Status != Verified || calls != 2 {
		t.Fatalf("retry: %v %q, %d loads", r.Status, r.Reason, calls)
	}
	v.VerifyBundle(b, subject)
	if calls != 2 {
		t.Fatalf("the trusted root should be loaded once, got %d loads", calls)
	}
}

func TestNewFromFile(t *testing.T) {
	s := newSigstore(t)
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, must[[]byte](t)(s.TrustedRootJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := NewFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := v.VerifyBundle(must[[]byte](t)(s.SignImage(subject, alice, issuer)), subject); r.Status != Verified {
		t.Fatalf("verify with trusted root file: %v %s", r.Status, r.Reason)
	}
	if _, err := NewFromFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing trusted root file should fail")
	}
	if v.Source() != "trusted_root.json" {
		t.Errorf("source %q", v.Source())
	}
	if got := NewPublicGood().Source(); got != "Sigstore public good" {
		t.Errorf("public good source %q", got)
	}
}

func TestBestAndStatus(t *testing.T) {
	if r := Best(nil); r.Status != Unverified || r.Reason != "no signature" {
		t.Errorf("Best(nil) = %+v", r)
	}
	got := Best([]Result{{Status: Unverified}, {Status: Invalid, Reason: "bad"}, {Status: Unverified}})
	if got.Status != Invalid || got.Reason != "bad" {
		t.Errorf("invalid should win over unverified: %+v", got)
	}
	got = Best([]Result{{Status: Invalid}, {Status: Verified, Signer: alice}, {Status: Invalid}})
	if got.Status != Verified || got.Signer != alice {
		t.Errorf("verified should win: %+v", got)
	}
	for s, want := range map[Status]string{Verified: "verified", Invalid: "invalid", Unverified: "unverified"} {
		if s.String() != want {
			t.Errorf("%d.String() = %q", s, s.String())
		}
	}
}

// fakeRegistry serves signature manifests and blobs from memory.
type fakeRegistry struct {
	manifests map[string]*oci.Manifest
	blobs     map[digest.Digest][]byte
	err       error
}

func (f *fakeRegistry) FetchManifestReference(_ context.Context, _, ref string) (*oci.Manifest, error) {
	if m, ok := f.manifests[ref]; ok {
		return m, nil
	}
	return nil, errors.New("manifest unknown")
}

func (f *fakeRegistry) FetchBlob(_ context.Context, _ string, d ocispec.Descriptor, _ int64) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if b, ok := f.blobs[d.Digest]; ok {
		return b, nil
	}
	return nil, errors.New("blob unknown")
}

func (f *fakeRegistry) layer(mediaType string, data []byte, ann map[string]string) ocispec.Descriptor {
	d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data)), Annotations: ann}
	f.blobs[d.Digest] = data
	return d
}

func (f *fakeRegistry) manifest(ref string, layers ...ocispec.Descriptor) {
	f.manifests[ref] = &oci.Manifest{Layers: layers}
}

func TestSignaturesFromRegistry(t *testing.T) {
	s := newSigstore(t)
	other := newSigstore(t)
	v := New(s.Material())
	f := &fakeRegistry{manifests: map[string]*oci.Manifest{}, blobs: map[digest.Digest][]byte{}}
	bundleType := "application/vnd.dev.sigstore.bundle.v0.3+json"

	f.manifest("sha256:good", f.layer(bundleType, must[[]byte](t)(s.SignImage(subject, alice, issuer)), nil))
	f.manifest("sha256:att", f.layer(bundleType, must[[]byte](t)(s.Attest(subject, "https://slsa.dev/provenance/v1", alice, issuer)), nil))
	badPayload, badAnn, _ := other.SignLegacy(subject, "mallory@example.com", issuer)
	goodPayload, goodAnn, _ := s.SignLegacy(subject, alice, issuer)
	f.manifest("sha256-x.sig",
		f.layer(MediaTypeSimpleSigning, badPayload, badAnn),
		f.layer(MediaTypeSimpleSigning, goodPayload, goodAnn),
		f.layer("application/octet-stream", []byte("ignored"), nil))
	f.manifest("sha256:empty")

	ref := func(r string) oci.SignatureRef {
		if strings.HasSuffix(r, ".sig") {
			return oci.SignatureRef{Format: oci.FormatCosign, Tag: r}
		}
		return oci.SignatureRef{Format: oci.FormatCosign, Descriptor: ocispec.Descriptor{Digest: digest.Digest(r)}}
	}
	results := v.Signatures(context.Background(), f, "repo", subject, []oci.SignatureRef{
		ref("sha256:good"),
		ref("sha256:att"),
		ref("sha256-x.sig"),
		ref("sha256:empty"),
		ref("sha256:missing"),
		{Format: oci.FormatNotation},
	})
	want := []struct {
		status Status
		reason string
	}{
		{Verified, ""},
		{Invalid, "not a signature"},
		{Verified, ""}, // one of two legacy signatures is valid
		{Unverified, "no cosign signature"},
		{Unverified, "cannot fetch signature"},
		{Unverified, "notation signatures are not verified yet"},
	}
	for i, w := range want {
		if results[i].Status != w.status || !strings.Contains(results[i].Reason, w.reason) {
			t.Errorf("signature %d: %v %q, want %v %q", i, results[i].Status, results[i].Reason, w.status, w.reason)
		}
	}

	if r := v.Attached(context.Background(), f, "repo", subject, ref("sha256:att")); r.Status != Verified || r.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("attestation as an attached artifact: %v %q", r.Status, r.PredicateType)
	}

	f.err = errors.New("network down")
	if r := v.Signature(context.Background(), f, "repo", subject, ref("sha256:good")); r.Status != Unverified || !strings.Contains(r.Reason, "network down") {
		t.Errorf("blob fetch error: %v %q", r.Status, r.Reason)
	}
}
