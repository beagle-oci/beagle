// Package sigtest creates cosign signatures for tests and demos. It signs
// with sigstore-go's virtual Sigstore instance (Fulcio, Rekor, CT log and
// timestamp authority in memory), so the results verify against Material or
// TrustedRootJSON and nothing else.
package sigtest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/opencontainers/go-digest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// PredicateCosignSign is the predicate of cosign image signatures.
const PredicateCosignSign = "https://sigstore.dev/cosign/sign/v1"

// Sigstore is a virtual Sigstore instance.
type Sigstore struct {
	ca *ca.VirtualSigstore
}

// New starts a virtual Sigstore instance with fresh keys.
func New() (*Sigstore, error) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		return nil, err
	}
	return &Sigstore{ca: vs}, nil
}

// noCTLogs hides the virtual CT log: its certificates carry no SCTs.
type noCTLogs struct{ root.TrustedMaterial }

func (noCTLogs) CTLogs() map[string]*root.TransparencyLog { return nil }

// Material is the trusted material to verify this instance's signatures.
// The virtual Fulcio issues certificates without SCTs, so it lists no CT log.
func (s *Sigstore) Material() root.TrustedMaterial { return noCTLogs{s.ca} }

// TrustedRootJSON returns Material as a trusted_root.json whose Rekor key
// does not expire, so demo data stays verifiable.
func (s *Sigstore) TrustedRootJSON() ([]byte, error) {
	logs := map[string]*root.TransparencyLog{}
	for id, l := range s.ca.RekorLogs() {
		c := *l
		// The virtual instance keeps the hex log ID as bytes; trusted roots
		// store the raw key ID.
		raw, err := hex.DecodeString(string(l.ID))
		if err != nil {
			return nil, err
		}
		c.ID, c.ValidityPeriodEnd = raw, time.Time{}
		logs[id] = &c
	}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		s.ca.FulcioCertificateAuthorities(), nil, s.ca.TimestampingAuthorities(), logs)
	if err != nil {
		return nil, err
	}
	return tr.MarshalJSON()
}

// nowForLeaf is the signing time: the virtual Fulcio issues certificates
// valid for ten minutes from now, and sigstore-go's own helpers sign five
// minutes in.
func nowForLeaf() time.Time { return time.Now().Add(5 * time.Minute) }

// statement is an in-toto v1 statement about one manifest digest.
func statement(subject digest.Digest, predicateType string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"digest": map[string]string{subject.Algorithm().String(): subject.Encoded()}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{},
	})
}

// SignImage signs subject the way cosign v3 does: a DSSE envelope with a
// cosign/sign statement in a v0.3 bundle.
func (s *Sigstore) SignImage(subject digest.Digest, identity, issuer string) ([]byte, error) {
	return s.Attest(subject, PredicateCosignSign, identity, issuer)
}

// Attest returns a v0.3 bundle with a DSSE statement about subject.
func (s *Sigstore) Attest(subject digest.Digest, predicateType, identity, issuer string) ([]byte, error) {
	body, err := statement(subject, predicateType)
	if err != nil {
		return nil, err
	}
	e, err := s.ca.AttestAtTime(identity, issuer, body, nowForLeaf(), true)
	if err != nil {
		return nil, err
	}
	return s.bundleJSON(e, "0.3")
}

// SignMessage returns a v0.1 bundle with a message signature over artifact,
// so the signed digest is sha256(artifact).
func (s *Sigstore) SignMessage(artifact []byte, identity, issuer string) ([]byte, error) {
	e, err := s.ca.SignAtTimeWithVersion(identity, issuer, artifact, nowForLeaf(), "v0.1")
	if err != nil {
		return nil, err
	}
	return s.bundleJSON(e, "0.1")
}

// SignLegacy signs subject the way cosign did before bundles: it returns
// the simple signing payload and the annotations of its layer.
func (s *Sigstore) SignLegacy(subject digest.Digest, identity, issuer string) ([]byte, map[string]string, error) {
	payload, err := json.Marshal(map[string]any{
		"critical": map[string]any{
			"identity": map[string]string{"docker-reference": "example.test/repo"},
			"image":    map[string]string{"docker-manifest-digest": subject.String()},
			"type":     "cosign container image signature",
		},
		"optional": nil,
	})
	if err != nil {
		return nil, nil, err
	}
	e, err := s.ca.SignAtTimeWithVersion(identity, issuer, payload, nowForLeaf(), "v0.1")
	if err != nil {
		return nil, nil, err
	}
	sc, err := e.SignatureContent()
	if err != nil {
		return nil, nil, err
	}
	vc, err := e.VerificationContent()
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := cryptoutils.MarshalCertificateToPEM(vc.Certificate())
	if err != nil {
		return nil, nil, err
	}
	tle, err := s.logEntry(e)
	if err != nil {
		return nil, nil, err
	}
	rb, err := json.Marshal(map[string]any{
		"SignedEntryTimestamp": tle.GetInclusionPromise().GetSignedEntryTimestamp(),
		"Payload": map[string]any{
			"body":           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
			"integratedTime": tle.GetIntegratedTime(),
			"logIndex":       tle.GetLogIndex(),
			"logID":          hex.EncodeToString(tle.GetLogId().GetKeyId()),
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return payload, map[string]string{
		"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sc.Signature()),
		"dev.sigstore.cosign/certificate":    string(certPEM),
		"dev.sigstore.cosign/bundle":         string(rb),
	}, nil
}

// logEntry completes the test entity's log entry with its kind and an
// inclusion promise, which the virtual instance does not export.
func (s *Sigstore) logEntry(e *ca.TestEntity) (*protorekor.TransparencyLogEntry, error) {
	entries, err := e.TlogEntries()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("no log entry")
	}
	tle, ok := proto.Clone(entries[0].TransparencyLogEntry()).(*protorekor.TransparencyLogEntry)
	if !ok {
		return nil, errors.New("unexpected log entry type")
	}
	var kind struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(tle.CanonicalizedBody, &kind); err != nil {
		return nil, err
	}
	tle.KindVersion = &protorekor.KindVersion{Kind: kind.Kind, Version: kind.APIVersion}
	set, err := s.ca.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.CanonicalizedBody),
		IntegratedTime: tle.IntegratedTime,
		LogIndex:       tle.LogIndex,
		LogID:          hex.EncodeToString(tle.LogId.KeyId),
	})
	if err != nil {
		return nil, err
	}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	return tle, nil
}

func (s *Sigstore) bundleJSON(e *ca.TestEntity, version string) ([]byte, error) {
	vc, err := e.VerificationContent()
	if err != nil {
		return nil, err
	}
	sc, err := e.SignatureContent()
	if err != nil {
		return nil, err
	}
	tle, err := s.logEntry(e)
	if err != nil {
		return nil, err
	}
	timestamps, err := e.Timestamps()
	if err != nil {
		return nil, err
	}
	mediaType, err := bundle.MediaTypeString(version)
	if err != nil {
		return nil, err
	}
	pb := &protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: vc.Certificate().Raw},
			},
			TlogEntries:               []*protorekor.TransparencyLogEntry{tle},
			TimestampVerificationData: &protobundle.TimestampVerificationData{},
		},
	}
	for _, ts := range timestamps {
		pb.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps = append(
			pb.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps,
			&protocommon.RFC3161SignedTimestamp{SignedTimestamp: ts})
	}
	if env := sc.EnvelopeContent(); env != nil {
		raw := env.RawEnvelope()
		payload, err := base64.StdEncoding.DecodeString(raw.Payload)
		if err != nil {
			return nil, err
		}
		de := &protodsse.Envelope{Payload: payload, PayloadType: raw.PayloadType}
		for _, sig := range raw.Signatures {
			b, err := base64.StdEncoding.DecodeString(sig.Sig)
			if err != nil {
				return nil, err
			}
			de.Signatures = append(de.Signatures, &protodsse.Signature{Sig: b, Keyid: sig.KeyID})
		}
		pb.Content = &protobundle.Bundle_DsseEnvelope{DsseEnvelope: de}
	} else {
		ms := sc.MessageSignatureContent()
		pb.Content = &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: ms.Digest()},
			Signature:     ms.Signature(),
		}}
	}
	if _, err := bundle.NewBundle(pb); err != nil {
		return nil, fmt.Errorf("invalid test bundle: %w", err)
	}
	return protojson.Marshal(pb)
}
