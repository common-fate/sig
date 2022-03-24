package sig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"time"

	sigv1alpha1 "github.com/common-fate/sig/sig/v1alpha1"

	"google.golang.org/protobuf/proto"
)

type AssumeAwsIamResults struct {
	AccessKeyID     string
	SecretAccessKey string
	Expiration      *time.Time
	SessionToken    string
}
type SignedAssumeAwsIamRequest struct {
	AssumeAwsIamRequest
	Sig []byte `json:"sig"`
}

type AssumeAwsIamRequest struct {
	AssumeRequest
	Role    string `json:"role"`
	Account string `json:"account"`
}

// Digest builds the canonical digest of the assume role
// payload which can be signed and verified.
func (a *AssumeAwsIamRequest) Digest() ([]byte, error) {
	assumeBase := a.AssumeRequest.Proto()
	p1 := sigv1alpha1.AssumeAwsIamSignature{
		Role:                a.Role,
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
func (a *AssumeAwsIamRequest) Sign(s crypto.Signer) ([]byte, error) {
	digest, err := a.Digest()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}
