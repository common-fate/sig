package sig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"

	"google.golang.org/protobuf/proto"
)

type AssumeAwsSsoResults struct {
}
type SignedAssumeAwsSsoRequest struct {
	AssumeAwsSsoRequest
	Sig []byte `json:"sig"`
}

type AssumeAwsSsoRequest struct {
	AssumeRequest
	Account string `json:"account"`
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *AssumeAwsSsoRequest) Digest() ([]byte, error) {
	assumeBase := a.AssumeRequest.Proto()
	p1 := sigv1alpha1.AssumeAwsSsoSignature{
		Account:             a.Account,
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
func (a *AssumeAwsSsoRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}
