package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"
)

// writeExpiredCert overwrites path with a self-signed certificate whose
// validity window has already elapsed. The certificate doesn't need to
// chain to anything real: certificatesMatchHosts only parses it and checks
// NotBefore/NotAfter plus (for server certs) DNS/IP SANs.
func writeExpiredCert(t *testing.T, path string, hosts []string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := leafTemplate("expired", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, hosts)
	tmpl.Subject = pkix.Name{CommonName: "expired"}
	tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
	tmpl.NotAfter = time.Now().Add(-24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pemEncodeCertificate(der), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureCertificatesRegeneratesExpiredCertificates(t *testing.T) {
	hosts := []string{"127.0.0.1"}

	for _, which := range []string{"self-signed", "ca", "ca-server", "mtls-client"} {
		which := which
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			bundle, err := ensureCertificates(dir, hosts)
			if err != nil {
				t.Fatal(err)
			}

			var target string
			switch which {
			case "self-signed":
				target = bundle.SelfSignedCert
			case "ca":
				target = bundle.CACert
			case "ca-server":
				target = bundle.CAServerCert
			case "mtls-client":
				target = bundle.MTLSClientCert
			}

			writeExpiredCert(t, target, hosts)

			expiredCert, err := readCertificate(target)
			if err != nil {
				t.Fatal(err)
			}
			if certificateIsCurrentlyValid(expiredCert) {
				t.Fatal("test setup error: expected the substituted certificate to be expired")
			}

			regenerated, err := ensureCertificates(dir, hosts)
			if err != nil {
				t.Fatal(err)
			}

			for _, path := range []string{
				regenerated.SelfSignedCert, regenerated.CACert,
				regenerated.CAServerCert, regenerated.MTLSClientCert,
			} {
				cert, err := readCertificate(path)
				if err != nil {
					t.Fatal(err)
				}
				if !certificateIsCurrentlyValid(cert) {
					t.Fatalf("expected all certificates to be regenerated and valid, but %s is not", path)
				}
			}
		})
	}
}

func TestEnsureCertificatesReusesValidCertificates(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"127.0.0.1"}

	first, err := ensureCertificates(dir, hosts)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(first.SelfSignedCert)
	if err != nil {
		t.Fatal(err)
	}

	second, err := ensureCertificates(dir, hosts)
	if err != nil {
		t.Fatal(err)
	}
	reusedBytes, err := os.ReadFile(second.SelfSignedCert)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalBytes) != string(reusedBytes) {
		t.Fatal("expected valid, matching certificates to be reused rather than regenerated")
	}
}
