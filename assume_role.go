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

type SignedAssumeRoleRequest struct {
	AssumeRoleRequest
	Sig []byte `json:"sig"`
}
type AssumeRoleRequest struct {
	Role            string   `json:"role"`
	Account         string   `json:"account"`
	Group           string   `json:"group"`
	CertFingerprint [32]byte `json:"cert"`
	Reason          *string  `json:"reason"`
	// TimeNanos is the timestamp in UTC nanoseconds since epoch
	TimeNanos int64 `json:"time"`
}

func (a *AssumeRoleRequest) Time() time.Time {
	return time.Unix(0, a.TimeNanos)
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *AssumeRoleRequest) Digest() ([]byte, error) {

	p1 := sigv1alpha1.AssumeRoleSignature{
		Role:                   a.Role,
		Account:                a.Account,
		Reason:                 a.Reason,
		Group:                  a.Group,
		Timestamp:              timestamppb.New(a.Time()),
		CertificateFingerprint: a.CertFingerprint[:],
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
func (a *AssumeRoleRequest) Valid(sig []byte, cert *x509.Certificate, opts ...func(*verifyConf)) error {
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

	digest, err := a.Digest()
	if err != nil {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("error building digest: %s", err.Error())}
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &ErrInvalidSignature{Reason: "certificate did not have ECDSA signing key"}
	}

	// check the timestamp in the payload matches
	if a.Time().After(cfg.Now) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is in the future", a.Time().UTC().Format(time.RFC3339))}
	}
	if a.Time().Before(cfg.Now.Add(-cfg.AllowedDuration)) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is too old", a.Time().UTC().Format(time.RFC3339))}
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
