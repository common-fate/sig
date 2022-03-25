package sig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestBuildAssumeRoleDigest(t *testing.T) {
	type test struct {
		input AssumeAwsIamRequest
		valid bool
	}

	tests := []test{
		{
			// this one hashes to the digest that is hardcoded in the test
			input: AssumeAwsIamRequest{

				Account: "12345",
				AssumeRequest: AssumeRequest{
					Role:            "test",
					CertFingerprint: [32]byte{0, 10, 20, 30},
					TimeNanos:       time.Unix(10, 10).UnixNano(),
				},
			},
			valid: true,
		},
		// other inputs should produce different hashes
		{
			input: AssumeAwsIamRequest{

				Account: "12345",
				AssumeRequest: AssumeRequest{
					Role:            "test",
					CertFingerprint: [32]byte{0, 10, 20, 30},
					TimeNanos:       time.Unix(10, 11).UnixNano()},
			},
			valid: false,
		},
		{
			input: AssumeAwsIamRequest{

				Account: "12345",
				AssumeRequest: AssumeRequest{
					Role:            "test",
					CertFingerprint: [32]byte{0, 10, 20},
					TimeNanos:       time.Unix(10, 10).UnixNano(),
				},
			},
			valid: false,
		},
	}

	expected := []byte{225, 188, 39, 220, 161, 200, 127, 42, 118, 123, 96, 37, 216, 191, 206, 24, 121, 208, 175, 78, 36, 223, 159, 152, 148, 35, 231, 239, 252, 169, 22, 143}

	for _, tc := range tests {
		digest, err := tc.input.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if tc.valid {
			if !bytes.Equal(digest, expected) {
				t.Fatalf("expected hashes to match: %+v, got: %+v", expected, digest)
			}
		} else {
			if bytes.Equal(digest, expected) {
				t.Fatalf("expected hashes to be different: %+v, got: %+v", expected, digest)
			}
		}
	}
}

func TestVerifyAssumeAwsIamRequest(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(11, 10),
		NotAfter:     time.Unix(12, 10),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	otherkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(10, 10).Add(time.Hour * 10),
	}
	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &otherkey.PublicKey, otherkey)
	if err != nil {
		t.Fatal(err)
	}
	othercert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	tmpl = x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &otherkey.PublicKey, otherkey)
	if err != nil {
		t.Fatal(err)
	}
	missingInforCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	req := AssumeAwsIamRequest{

		Account: "12345",
		AssumeRequest: AssumeRequest{
			Role:            "test",
			CertFingerprint: [32]byte{0, 10, 20, 30},
			TimeNanos:       time.Unix(10, 10).UnixNano(),
		},
	}

	type test struct {
		useInvalidData bool
		cert           *x509.Certificate
		time           time.Time
		err            error
	}

	tests := map[string]test{

		"valid":                         {useInvalidData: false, time: time.Unix(11, 10), cert: cert, err: nil},
		"invalid data":                  {useInvalidData: true, time: time.Unix(11, 10), cert: cert, err: &ErrInvalidSignature{Reason: "signature is invalid"}},
		"invalid cert":                  {useInvalidData: false, time: time.Unix(11, 10), cert: cert, err: &ErrInvalidSignature{Reason: "signature is invalid"}},
		"certificate not yet valid":     {useInvalidData: false, time: time.Unix(0, 0), cert: cert, err: &ErrInvalidSignature{Reason: "certificate is not valid until 1970-01-01T00:00:11Z"}},
		"certificate expired":           {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: cert, err: &ErrInvalidSignature{Reason: "certificate already expired at 1970-01-01T00:00:12Z"}},
		"certificate missing NotBefore": {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: missingInforCert, err: &ErrInvalidSignature{Reason: "certificate does not have a validity interval specified"}},
		"certificate missing NotAfter":  {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: missingInforCert, err: &ErrInvalidSignature{Reason: "certificate does not have a validity interval specified"}},
		"signature in future":           {useInvalidData: false, time: time.Unix(0, 0), cert: othercert, err: &ErrInvalidSignature{Reason: "payload time 1970-01-01T00:00:10Z is in the future"}},
		"signature too far in past":     {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: othercert, err: &ErrInvalidSignature{Reason: "payload time 1970-01-01T00:00:10Z is too old"}},
	}

	for name, tc := range tests {

		sig, err := req.Sign(priv)
		if err != nil {
			t.Fatal(err)
		}

		signed := &SignedAssumeAwsIamRequest{
			AssumeAwsIamRequest: req,
			Sig:                 sig,
		}

		if tc.useInvalidData {
			// change the data so the payload being verified is different
			signed.AssumeAwsIamRequest.Account = "different"
		}

		err = Valid(signed, tc.cert, WithVerificationTime(tc.time, 5*time.Minute))
		if tc.err == nil && err != nil {
			t.Fatalf("%s: expected no error but got: %+v", name, err)
		}
		if tc.err != nil && err != nil {
			if tc.err.Error() != err.Error() {
				t.Fatalf("%s: expected: %+v, got: %+v", name, tc.err, err)
			}
		}
	}
}
