package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestVerifyEnrollAccessHandlerRequest(t *testing.T) {
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

	der, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	invalidCertWithValidPrivkey, err := x509.ParseCertificate(der)
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

	fingerprint := sha256.Sum256(cert.Raw)

	req := EnrollAccessHandlerRequest{
		Token:            "12345",
		ProviderID:       "aws",
		AccessHandlerURL: "http://test.com",
		CertFingerprint:  fingerprint,
		TimeNanos:        time.Unix(10, 10).UnixNano(),
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
		"signature in future":           {useInvalidData: false, time: time.Unix(0, 0), cert: othercert, err: &ErrInvalidSignature{Reason: "signature time 1970-01-01T00:00:10Z is in the future"}},
		"signature too far in past":     {useInvalidData: false, time: time.Unix(10, 10).Add(time.Hour * 10), cert: othercert, err: &ErrInvalidSignature{Reason: "signature time 1970-01-01T00:00:10Z is too old"}},
		"invalid fingerprint":           {useInvalidData: false, time: time.Unix(11, 10), cert: invalidCertWithValidPrivkey, err: &ErrInvalidSignature{Reason: "certificate fingerprint did not match payload"}},
	}

	for name, tc := range tests {
		sig, err := req.Sign(priv)
		if err != nil {
			t.Fatal(err)
		}

		if tc.useInvalidData {
			// change the data so the payload being verified is different
			req.ProviderID = "different"
		}

		err = req.Valid(sig, tc.cert, WithVerificationTime(tc.time, 5*time.Minute))
		if tc.err == nil && err != nil {
			t.Fatalf("%s: expected no error but got: %+v", name, err)
		} else if tc.err != nil && err != nil {
			if tc.err.Error() != err.Error() {
				t.Fatalf("%s: expected: %+v, got: %+v", name, tc.err, err)
			}
		} else if err != nil {
			t.Fatalf("unhandled err: %s", err)
		}
	}
}
