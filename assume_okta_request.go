package sig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"

	"google.golang.org/protobuf/proto"
)

type AssumeOktaResults struct {
}
type SignedAssumeOktaRequest struct {
	AssumeOktaRequest
	Sig []byte `json:"sig"`
}

type AssumeOktaRequest struct {
	AssumeRequest
	Group string `json:"group"`
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *AssumeOktaRequest) Digest() ([]byte, error) {
	assumeBase := a.AssumeRequest.Proto()
	p1 := sigv1alpha1.AssumeOktaSignature{
		Group:               a.Group,
		AssumeSignatureBase: &assumeBase,
	}

	msg, err := proto.Marshal(&p1)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(msg)

	return hash[:], nil
}

// Sign an AssumeRole request.
func (a *AssumeOktaRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}
