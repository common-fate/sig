package sig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestBuildAssumeRoleDigest(t *testing.T) {
	type test struct {
		input AssumeRoleRequest
		valid bool
	}

	tests := []test{
		{
			// this one hashes to the digest that is hardcoded in the test
			input: AssumeRoleRequest{
				Role:            "test",
				Account:         "12345",
				CertFingerprint: []byte{0, 10, 20, 30},
				Time:            time.Unix(10, 10),
			},
			valid: true,
		},
		// other inputs should produce different hashes
		{
			input: AssumeRoleRequest{
				Role:            "test",
				Account:         "12345",
				CertFingerprint: []byte{0, 10, 20, 30},
				Time:            time.Unix(10, 11),
			},
			valid: false,
		},
		{
			input: AssumeRoleRequest{
				Role:            "test",
				Account:         "12345",
				CertFingerprint: []byte{0, 10, 20},
				Time:            time.Unix(10, 10),
			},
			valid: false,
		},
	}

	expected := []byte{128, 102, 227, 125, 169, 6, 16, 5, 57, 122, 3, 34, 188, 138, 134, 165, 84, 215, 21, 49, 132, 98, 199, 244, 83, 53, 238, 218, 137, 233, 104, 112}

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

func TestVerifyAssumeRoleRequest(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
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
	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &otherkey.PublicKey, otherkey)
	if err != nil {
		t.Fatal(err)
	}
	othercert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	req := AssumeRoleRequest{
		Role:            "test",
		Account:         "12345",
		CertFingerprint: []byte{0, 10, 20, 30},
		Time:            time.Unix(10, 10),
	}

	type test struct {
		useInvalidData bool
		cert           *x509.Certificate
		time           time.Time
		shouldBeValid  bool
		err            error
	}

	tests := map[string]test{
		"valid":                     {useInvalidData: false, time: time.Unix(11, 10), cert: cert, shouldBeValid: true},
		"invalid data":              {useInvalidData: true, time: time.Unix(11, 10), cert: cert, shouldBeValid: false},
		"invalid cert":              {useInvalidData: false, time: time.Unix(11, 10), cert: othercert, shouldBeValid: false},
		"signature in future":       {useInvalidData: false, time: time.Unix(0, 0), cert: othercert, shouldBeValid: false, err: &ErrInvalidTimestamp{}},
		"signature too far in past": {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: othercert, shouldBeValid: false, err: &ErrInvalidTimestamp{}},
	}

	for name, tc := range tests {

		sig, err := req.Sign(priv)
		if err != nil {
			t.Fatal(err)
		}

		r := req
		if tc.useInvalidData {
			// change the data so the payload being verified is different
			r.Account = "different"
		}

		valid, err := r.Valid(sig, tc.cert, WithVerificationTime(tc.time, 5*time.Minute))
		if tc.err != nil {
			errMatches := errors.As(err, &tc.err)
			if !errMatches {
				t.Fatalf("%s: expected error: %v, got: %v", name, tc.err, err)
			}
		} else {
			if err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}
		}

		if tc.shouldBeValid != valid {
			t.Fatalf("%s: expected valid: %v, got: %v", name, tc.shouldBeValid, valid)
		}
	}
}
