package sigv1alpha1

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

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
	p1 := AssumeRoleSignature{
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

type ErrInvalidTimestamp struct {
	Now           time.Time
	SignatureTime time.Time
}

func (e *ErrInvalidTimestamp) Error() string {
	return fmt.Sprintf("signature timestamp %s was invalid (current time: %s)", e.SignatureTime.Format(time.RFC3339), e.Now.Format(time.RFC3339))
}

// Valid verifies that a signature is valid. It performs the following checks:
//
// 1. Is the payload signature provided valid for the certificate?
//
// 2. Is the timestamp in the payload valid?
//
// Timestamps are considered valid if they have occurred up to 5 minutes before time.Now().
// sig.WithVerificationTime() can be passed to customise this.
func (a *AssumeRoleRequest) Valid(sig []byte, cert *x509.Certificate, opts ...func(*verifyConf)) (bool, error) {
	cfg := &verifyConf{
		Now:             time.Now(),
		AllowedDuration: time.Minute * 5,
	}
	for _, o := range opts {
		o(cfg)
	}

	digest, err := a.Digest()
	if err != nil {
		return false, err
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("certificate did not have ECDSA signing key")
	}

	// check the timestamp in the payload matches
	if a.Time.After(cfg.Now) {
		return false, &ErrInvalidTimestamp{Now: cfg.Now, SignatureTime: a.Time}
	}
	if a.Time.Before(cfg.Now.Add(-cfg.AllowedDuration)) {
		return false, &ErrInvalidTimestamp{Now: cfg.Now, SignatureTime: a.Time}
	}

	valid := ecdsa.VerifyASN1(key, digest, sig)
	return valid, nil
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
