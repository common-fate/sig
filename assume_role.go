package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AssumeRoleRequest struct {
	Role            string
	Account         string
	CertFingerprint []byte
	Time            time.Time
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *AssumeRoleRequest) Digest() ([]byte, error) {
	p1 := sigv1alpha1.AssumeRoleSignature{
		Role:                   a.Role,
		Account:                a.Account,
		Timestamp:              timestamppb.New(a.Time),
		CertificateFingerprint: a.CertFingerprint,
	}
	msg, err := proto.Marshal(&p1)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(msg)

	return hash[:], nil
}

// Sign an AssumeRole request.
func (a *AssumeRoleRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}

type ErrInvalidSignature struct {
	Reason string
}

func (e ErrInvalidSignature) Error() string { return e.Reason }

// Valid verifies that a signature is valid. It performs the following checks:
//
// 1. Is the payload signature provided valid for the certificate?
//
// 2. Is the timestamp in the payload valid?
//
// Timestamps are considered valid if they have occurred up to 5 minutes before time.Now().
// sig.WithVerificationTime() can be passed to customise this.
func (a *AssumeRoleRequest) Valid(sig []byte, cert *x509.Certificate, opts ...func(*verifyConf)) error {
	cfg := &verifyConf{
		Now:             time.Now(),
		AllowedDuration: time.Minute * 5,
	}
	for _, o := range opts {
		o(cfg)
	}

	digest, err := a.Digest()
	if err != nil {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("error building digest: %s", err.Error())}
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &ErrInvalidSignature{Reason: "certificate did not have ECDSA signing key"}
	}

	// check the timestamp in the payload matches
	if a.Time.After(cfg.Now) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is in the future", a.Time.Format(time.RFC3339))}
	}
	if a.Time.Before(cfg.Now.Add(-cfg.AllowedDuration)) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is too old", a.Time.Format(time.RFC3339))}
	}

	valid := ecdsa.VerifyASN1(key, digest, sig)
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