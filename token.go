package sig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"
	"google.golang.org/protobuf/proto"
)

type TokenContextResults struct {
	Token string
	Title string
}
type SignedTokenContextRequest struct {
	TokenContextRequest
	Sig []byte `json:"sig"`
}
type TokenContextRequest struct {
	TriggerToken    *string  `json:"token"`
	CertFingerprint [32]byte `json:"cert"`

	// TimeNanos is the timestamp in UTC nanoseconds since epoch
	TimeNanos int64 `json:"time"`
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *TokenContextRequest) Digest() ([]byte, error) {

	p1 := sigv1alpha1.TokenContextSignature{
		Token:                  *a.TriggerToken,
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
func (a *TokenContextRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}
