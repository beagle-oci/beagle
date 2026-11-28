// Package sigverify verifies cosign signatures with sigstore-go: Sigstore
// bundles as written by cosign v2 (--new-bundle-format) and v3, and the
// legacy layout with sha256-<hex>.sig tags.
//
// A verified signature has a valid Fulcio certificate chain, a valid
// certificate transparency proof, a transparency log entry and a signature
// over the subject digest. Who signed is reported, not judged: the caller
// shows the identity and leaves the trust decision to the user.
package sigverify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/beagle-oci/beagle/internal/oci"
)

// Status is the outcome of a signature check.
type Status int

// Statuses, ordered so that a higher one describes a set of signatures
// better (see Best).
const (
	// Unverified means the signature could not be checked: unsupported
	// format, signed with a key instead of a certificate, or the trusted
	// root or the registry was unavailable.
	Unverified Status = iota
	// Invalid means the signature, its certificate, its log entry or its
	// subject does not check out.
	Invalid
	// Verified means the signature is valid for the subject.
	Verified
)

func (s Status) String() string {
	switch s {
	case Verified:
		return "verified"
	case Invalid:
		return "invalid"
	default:
		return "unverified"
	}
}

// Result describes the verification of one signature.
type Result struct {
	Status Status
	// Format is the signature format, e.g. oci.FormatCosign.
	Format string
	// Reason explains an invalid or unverified result.
	Reason string

	// Signer is the identity in the signing certificate: an email address
	// or a URI such as a CI workflow.
	Signer string
	// Issuer is the OIDC issuer that vouched for Signer.
	Issuer string
	// SourceRepository and SourceRevision are set for CI identities, e.g.
	// GitHub Actions.
	SourceRepository string
	SourceRevision   string
	// Time is when the signature was made according to the transparency
	// log or a timestamp authority.
	Time time.Time
	// LogIndex is the transparency log index, -1 if unknown.
	LogIndex int64
	// PredicateType is the in-toto predicate of a DSSE bundle.
	PredicateType string
}

func newResult(format string) Result { return Result{Format: format, LogIndex: -1} }

func (r Result) with(s Status, format string, args ...any) Result {
	r.Status = s
	r.Reason = fmt.Sprintf(format, args...)
	return r
}

func (r Result) invalid(format string, args ...any) Result {
	return r.with(Invalid, format, args...)
}

func (r Result) unverified(format string, args ...any) Result {
	return r.with(Unverified, format, args...)
}

// Best picks the result that describes a set of signatures: one verified
// signature is enough; otherwise an invalid one is worth reporting before
// an unverified one.
func Best(results []Result) Result {
	best := newResult(oci.FormatCosign)
	best.Reason = "no signature"
	for i, r := range results {
		if i == 0 || r.Status > best.Status {
			best = r
		}
	}
	return best
}

// errorRetry is how long a failure to load the trusted root is reported
// before the next attempt.
const errorRetry = time.Minute

// Verifier checks signatures against Sigstore trusted material. It is safe
// for concurrent use and loads the trusted material on first use.
type Verifier struct {
	source string
	load   func() (root.TrustedMaterial, error)
	now    func() time.Time

	mu       sync.Mutex
	verifier *verify.Verifier
	err      error
	failedAt time.Time
}

// New verifies against the given trusted material.
func New(material root.TrustedMaterial) *Verifier {
	return newVerifier("custom trusted root", func() (root.TrustedMaterial, error) { return material, nil })
}

// NewPublicGood verifies against the Sigstore public-good instance, the one
// cosign uses by default. The trusted root is fetched and verified via TUF
// on first use and cached in ~/.sigstore/root, shared with cosign.
func NewPublicGood() *Verifier {
	return newVerifier("Sigstore public good", func() (root.TrustedMaterial, error) {
		return root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithCacheValidity(1))
	})
}

// NewFromFile verifies against a trusted_root.json, e.g. of a private
// Sigstore instance or for offline use.
func NewFromFile(path string) (*Verifier, error) {
	tr, err := root.NewTrustedRootFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("read trusted root: %w", err)
	}
	v := New(tr)
	v.source = filepath.Base(path)
	return v, nil
}

func newVerifier(source string, load func() (root.TrustedMaterial, error)) *Verifier {
	return &Verifier{source: source, load: load, now: time.Now}
}

// Source names the trusted material, e.g. "Sigstore public good".
func (v *Verifier) Source() string { return v.source }

// sigstoreVerifier returns the sigstore-go verifier, loading the trusted
// material the first time. Failures are cached for errorRetry.
func (v *Verifier) sigstoreVerifier() (*verify.Verifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	if v.err != nil && v.now().Sub(v.failedAt) < errorRetry {
		return nil, v.err
	}
	material, err := v.load()
	if err == nil {
		// Like cosign: a transparency log entry and a trusted time from the
		// log or a timestamp authority are required, and certificate
		// transparency proofs (SCTs) wherever the instance runs a CT log, as
		// the public-good instance does.
		opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
		if len(material.CTLogs()) > 0 {
			opts = append(opts, verify.WithSignedCertificateTimestamps(1))
		}
		v.verifier, err = verify.NewVerifier(material, opts...)
	}
	if err != nil {
		v.err, v.failedAt = fmt.Errorf("trusted root unavailable: %w", err), v.now()
		return nil, v.err
	}
	return v.verifier, nil
}

// VerifyBundle verifies a Sigstore bundle for the manifest digest subject.
// DSSE bundles must name the subject in their statement, message signatures
// must sign it.
func (v *Verifier) VerifyBundle(data []byte, subject digest.Digest) Result {
	res := newResult(oci.FormatCosign)
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return res.invalid("cannot parse bundle: %v", err)
	}
	policy, err := digestPolicy(subject)
	if err != nil {
		return res.invalid("%v", err)
	}
	return v.verifyEntity(&b, policy, res)
}

// Annotations of legacy cosign signature layers.
const (
	annotationSignature   = "dev.cosignproject.cosign/signature"
	annotationCertificate = "dev.sigstore.cosign/certificate"
	annotationChain       = "dev.sigstore.cosign/chain"
	annotationBundle      = "dev.sigstore.cosign/bundle"
)

// MediaTypeSimpleSigning is the layer type of legacy cosign signatures.
const MediaTypeSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"

// simpleSigning is the part of the cosign simple signing payload that binds
// a signature to an image.
type simpleSigning struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
}

// rekorBundle is the Rekor inclusion promise cosign stores in the
// dev.sigstore.cosign/bundle annotation.
type rekorBundle struct {
	SignedEntryTimestamp []byte
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}
}

// VerifyLegacy verifies a signature in the layout cosign used before
// bundles: a simple signing payload whose layer annotations carry the
// signature, the Fulcio certificate and the Rekor inclusion promise.
func (v *Verifier) VerifyLegacy(payload []byte, annotations map[string]string, subject digest.Digest) Result {
	res := newResult(oci.FormatCosign)
	var ss simpleSigning
	if err := json.Unmarshal(payload, &ss); err != nil {
		return res.invalid("cannot parse signature payload: %v", err)
	}
	if got := ss.Critical.Image.DockerManifestDigest; got != subject.String() {
		return res.invalid("signature is for %s, not %s", got, subject)
	}
	sig, err := base64.StdEncoding.DecodeString(annotations[annotationSignature])
	if err != nil || len(sig) == 0 {
		return res.invalid("missing or malformed signature annotation")
	}
	if strings.TrimSpace(annotations[annotationCertificate]) == "" {
		return res.unverified("signed with a key, not a Sigstore certificate")
	}
	certs, err := parseCertificates(annotations[annotationCertificate] + "\n" + annotations[annotationChain])
	if err != nil {
		return res.invalid("cannot parse certificate: %v", err)
	}
	if annotations[annotationBundle] == "" {
		return res.invalid("not recorded in a transparency log")
	}
	tle, err := legacyLogEntry(annotations[annotationBundle])
	if err != nil {
		return res.invalid("cannot parse transparency log entry: %v", err)
	}

	chain := make([]*protocommon.X509Certificate, len(certs))
	for i, c := range certs {
		chain[i] = &protocommon.X509Certificate{RawBytes: c.Raw}
	}
	sum := sha256.Sum256(payload)
	mediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return res.invalid("%v", err)
	}
	b, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{Certificates: chain},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{tle},
		},
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: sum[:]},
			Signature:     sig,
		}},
	})
	if err != nil {
		return res.invalid("%v", err)
	}
	return v.verifyEntity(b, verify.WithArtifact(bytes.NewReader(payload)), res)
}

// legacyLogEntry turns the dev.sigstore.cosign/bundle annotation into a
// transparency log entry with an inclusion promise.
func legacyLogEntry(annotation string) (*protorekor.TransparencyLogEntry, error) {
	var rb rekorBundle
	if err := json.Unmarshal([]byte(annotation), &rb); err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(rb.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	logID, err := hex.DecodeString(rb.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("log ID: %w", err)
	}
	var kind struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(body, &kind); err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	return &protorekor.TransparencyLogEntry{
		LogIndex:          rb.Payload.LogIndex,
		LogId:             &protocommon.LogId{KeyId: logID},
		KindVersion:       &protorekor.KindVersion{Kind: kind.Kind, Version: kind.APIVersion},
		IntegratedTime:    rb.Payload.IntegratedTime,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: rb.SignedEntryTimestamp},
		CanonicalizedBody: body,
	}, nil
}

func parseCertificates(data string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate")
	}
	return certs, nil
}

func digestPolicy(subject digest.Digest) (verify.ArtifactPolicyOption, error) {
	if err := subject.Validate(); err != nil {
		return nil, fmt.Errorf("invalid subject digest: %w", err)
	}
	raw, err := hex.DecodeString(subject.Encoded())
	if err != nil {
		return nil, err
	}
	return verify.WithArtifactDigest(subject.Algorithm().String(), raw), nil
}

// verifyEntity runs the sigstore-go verification and fills res from the
// verified certificate, timestamps and statement.
func (v *Verifier) verifyEntity(e verify.SignedEntity, artifact verify.ArtifactPolicyOption, res Result) Result {
	content, err := e.VerificationContent()
	if err != nil {
		return res.invalid("%v", err)
	}
	if content.Certificate() == nil {
		return res.unverified("signed with a key, not a Sigstore certificate")
	}
	sv, err := v.sigstoreVerifier()
	if err != nil {
		return res.unverified("%v", err)
	}
	out, err := sv.Verify(e, verify.NewPolicy(artifact, verify.WithoutIdentitiesUnsafe()))
	if err != nil {
		return res.invalid("%v", err)
	}
	res.Status, res.Reason = Verified, ""
	if out.Signature != nil && out.Signature.Certificate != nil {
		c := out.Signature.Certificate
		res.Signer, res.Issuer = c.SubjectAlternativeName, c.Issuer
		res.SourceRepository, res.SourceRevision = c.SourceRepositoryURI, c.SourceRepositoryDigest
	}
	for _, ts := range out.VerifiedTimestamps {
		if res.Time.IsZero() || ts.Timestamp.Before(res.Time) {
			res.Time = ts.Timestamp
		}
	}
	if out.Statement != nil {
		res.PredicateType = out.Statement.PredicateType
	}
	if entries, err := e.TlogEntries(); err == nil && len(entries) > 0 {
		res.LogIndex = entries[0].LogIndex()
	}
	return res
}
