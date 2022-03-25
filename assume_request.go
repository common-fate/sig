package sig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// AssumeRequest contains fields that are common across all access request types
// Fields that are unique to a request type, for exampel Okta requires a Group.
// Should be added on the specific request type which inherits from this base type
type AssumeRequest struct {
	Role            string   `json:"role"`
	CertFingerprint [32]byte `json:"cert"`
	Reason          *string  `json:"reason"`
	// Used to identify an approval request that belongs to this request.
	// The access handler will use this to make a decision about whether this request is actually approved.
	RoleAccessRequestMerkleHash []byte `json:"rarMerkleHash"`
	// TimeNanos is the timestamp in UTC nanoseconds since epoch
	TimeNanos int64 `json:"time"`
}

func (a *AssumeRequest) Time() time.Time {
	return time.Unix(0, a.TimeNanos)
}

func (a *AssumeRequest) Proto() sigv1alpha1.AssumeSignature {
	return sigv1alpha1.AssumeSignature{
		Role:                        a.Role,
		Reason:                      a.Reason,
		Timestamp:                   timestamppb.New(a.Time()),
		CertificateFingerprint:      a.CertFingerprint[:],
		RoleAccessRequestMerkleHash: a.RoleAccessRequestMerkleHash,
	}
}

// This interface makes it simple to support many request types
type SignedDigestible interface {
	// convert the payload to a hashable format and return the hash
	Digest() ([]byte, error)
	// The time of the request
	Time() time.Time
	// The signature of the request.
	// This is validated against the digest to prove that the bearer of the certificate has access to the private key
	Signature() []byte
}

type ErrInvalidSignature struct {
	Reason string
}

func (e ErrInvalidSignature) Error() string { return e.Reason }

type ErrInvalidCertificate struct {
	Reason string
}

func (e ErrInvalidCertificate) Error() string { return e.Reason }

// Valid verifies that a signature is valid. It performs the following checks:
// 1. Is the certificate missing validity interval information
//
// 2. Is the certificate expired or not yet valid
//
// 3. Is the payload signature provided valid for the certificate?
//
// 4. Is the timestamp in the payload valid?
//
// Timestamps are considered valid if they have occurred up to 5 minutes before time.Now().
// sig.WithVerificationTime() can be passed to customise this.
func Valid(signedPayload SignedDigestible, cert *x509.Certificate, opts ...func(*verifyConf)) error {
	cfg := &verifyConf{
		Now:             time.Now(),
		AllowedDuration: time.Minute * 5,
	}
	for _, o := range opts {
		o(cfg)
	}

	// certificates must have NotBefore and NotAfter specified
	var zeroTime time.Time
	if cert.NotAfter.Equal(zeroTime) || cert.NotBefore.Equal(zeroTime) {
		return &ErrInvalidSignature{Reason: "certificate does not have a validity interval specified"}
	}
	// certificates MUST be valid before a request is made
	certificateNotYetValid := cert.NotBefore.After(cfg.Now)
	if certificateNotYetValid {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("certificate is not valid until %s", cert.NotBefore.UTC().Format(time.RFC3339))}
	}

	// certificates can have expired within the AllowedDuration
	certificateExpired := cert.NotAfter.Before(cfg.Now.Add(-cfg.AllowedDuration))
	if certificateExpired {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("certificate already expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))}
	}
	digest, err := signedPayload.Digest()
	if err != nil {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("error building digest: %s", err.Error())}
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &ErrInvalidSignature{Reason: "certificate did not have ECDSA signing key"}
	}

	// check the timestamp in the payload matches
	if signedPayload.Time().After(cfg.Now) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("payload time %s is in the future", signedPayload.Time().UTC().Format(time.RFC3339))}
	}
	if signedPayload.Time().Before(cfg.Now.Add(-cfg.AllowedDuration)) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("payload time %s is too old", signedPayload.Time().UTC().Format(time.RFC3339))}
	}

	valid := ecdsa.VerifyASN1(key, digest, signedPayload.Signature())
	if !valid {
		return &ErrInvalidSignature{Reason: "signature is invalid"}
	}
	return nil
}

type verifyConf struct {
	Now             time.Time
	AllowedDuration time.Duration
}

// WithVerificationTime allows customising the time that the timestamp in the
// signature is verified against.
func WithVerificationTime(t time.Time, d time.Duration) func(*verifyConf) {
	return func(vc *verifyConf) {
		vc.Now = t
		vc.AllowedDuration = d
	}
}
