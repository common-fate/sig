package sig

import (
	"bytes"
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

type EnrollAccessHandlerRequest struct {
	Token            string   `json:"token"`
	ProviderID       string   `json:"providerId"`
	AccessHandlerURL string   `json:"accessHandlerUrl"`
	CertFingerprint  [32]byte `json:"cert"`
	TimeNanos        int64    `json:"time"`
}

type SignedEnrollAccessHandlerRequest struct {
	EnrollAccessHandlerRequest
	Sig []byte `json:"sig"`
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *EnrollAccessHandlerRequest) Digest() ([]byte, error) {
	p1 := sigv1alpha1.EnrollAccessHandlerSignature{
		Token:                  a.Token,
		ProviderId:             a.ProviderID,
		AccessHandlerUrl:       a.AccessHandlerURL,
		Timestamp:              timestamppb.New(time.Unix(0, a.TimeNanos)),
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
func (a *EnrollAccessHandlerRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}

// Valid verifies that a signature is valid. It performs the following checks:
//
// 1. Is the payload signature provided valid for the certificate?
//
// 2. Is the timestamp in the payload valid?
//
// 3. Does the certificate match the fingerprint provided in the payload?
//
// Timestamps are considered valid if they have occurred up to 5 minutes before time.Now().
// sig.WithVerificationTime() can be passed to customise this.
func (a *EnrollAccessHandlerRequest) Valid(sig []byte, cert *x509.Certificate, opts ...func(*verifyConf)) error {
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

	plTime := time.Unix(0, a.TimeNanos)

	// check the timestamp in the payload matches
	if plTime.After(cfg.Now) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is in the future", plTime.UTC().Format(time.RFC3339))}
	}
	if plTime.Before(cfg.Now.Add(-cfg.AllowedDuration)) {
		return &ErrInvalidSignature{Reason: fmt.Sprintf("signature time %s is too old", plTime.UTC().Format(time.RFC3339))}
	}

	valid := ecdsa.VerifyASN1(key, digest, sig)
	if !valid {
		return &ErrInvalidSignature{Reason: "signature is invalid"}
	}

	// data verification:
	// verify that the fingerprint of the signing certificate matches the fingerprint provided in the payload

	fingerprint := sha256.Sum256(cert.Raw)
	if !bytes.Equal(fingerprint[:], a.CertFingerprint[:]) {
		return &ErrInvalidSignature{Reason: "certificate fingerprint did not match payload"}
	}

	return nil
}
