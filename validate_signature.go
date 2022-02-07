package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func ValidateProtoMessageSignature(payload protoreflect.ProtoMessage, signatureToVerify []byte, certificateToVerify *x509.Certificate) (bool, error) {
	// payload must be signed by the submitter
	signingBytes, err := proto.Marshal(payload)
	if err != nil {
		return false, err
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(signingBytes)
	if err != nil {
		return false, err
	}
	hash := hasher.Sum(nil)
	pubkey, ok := certificateToVerify.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("peer certificate public key was not ECDSA")
	}

	return ecdsa.VerifyASN1(pubkey, hash, signatureToVerify), nil

}
