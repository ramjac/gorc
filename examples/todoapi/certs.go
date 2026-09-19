package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const certificateLifetime = 365 * 24 * time.Hour

type certificateBundle struct {
	Dir            string
	SelfSignedCert string
	SelfSignedKey  string
	CACert         string
	CAKey          string
	CAServerCert   string
	CAServerKey    string
	MTLSClientCert string
	MTLSClientKey  string
}

func defaultCertificateDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("examples", "todoapi", "generated")
	}
	return filepath.Join(filepath.Dir(file), "generated")
}

func ensureCertificates(dir string) (certificateBundle, error) {
	bundle := certificateBundle{
		Dir:            dir,
		SelfSignedCert: filepath.Join(dir, "selfsigned-cert.pem"),
		SelfSignedKey:  filepath.Join(dir, "selfsigned-key.pem"),
		CACert:         filepath.Join(dir, "demo-ca-cert.pem"),
		CAKey:          filepath.Join(dir, "demo-ca-key.pem"),
		CAServerCert:   filepath.Join(dir, "ca-server-cert.pem"),
		CAServerKey:    filepath.Join(dir, "ca-server-key.pem"),
		MTLSClientCert: filepath.Join(dir, "mtls-client-cert.pem"),
		MTLSClientKey:  filepath.Join(dir, "mtls-client-key.pem"),
	}
	if certificatesExist(bundle) {
		return bundle, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return bundle, err
	}

	caCertPEM, caKeyPEM, caCert, caKey, err := generateCA("gorc demo CA")
	if err != nil {
		return bundle, err
	}
	selfCertPEM, selfKeyPEM, err := generateSelfSignedServerCert("gorc demo self-signed")
	if err != nil {
		return bundle, err
	}
	caServerCertPEM, caServerKeyPEM, err := generateSignedLeaf(caCert, caKey, "gorc demo CA server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return bundle, err
	}
	mtlsClientCertPEM, mtlsClientKeyPEM, err := generateSignedLeaf(caCert, caKey, "gorc demo client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return bundle, err
	}

	files := map[string][]byte{
		bundle.CACert:         caCertPEM,
		bundle.CAKey:          caKeyPEM,
		bundle.SelfSignedCert: selfCertPEM,
		bundle.SelfSignedKey:  selfKeyPEM,
		bundle.CAServerCert:   caServerCertPEM,
		bundle.CAServerKey:    caServerKeyPEM,
		bundle.MTLSClientCert: mtlsClientCertPEM,
		bundle.MTLSClientKey:  mtlsClientKeyPEM,
	}
	for path, data := range files {
		mode := os.FileMode(0o644)
		if filepath.Ext(path) == ".pem" && filepath.Base(path) != "selfsigned-cert.pem" && filepath.Base(path) != "demo-ca-cert.pem" && filepath.Base(path) != "ca-server-cert.pem" && filepath.Base(path) != "mtls-client-cert.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			return bundle, err
		}
	}
	return bundle, nil
}

func certificatesExist(bundle certificateBundle) bool {
	for _, path := range []string{bundle.SelfSignedCert, bundle.SelfSignedKey, bundle.CACert, bundle.CAKey, bundle.CAServerCert, bundle.CAServerKey, bundle.MTLSClientCert, bundle.MTLSClientKey} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func generateCA(commonName string) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pemEncodeCertificate(der), pemEncodeECPrivateKey(key), cert, key, nil
}

func generateSelfSignedServerCert(commonName string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := leafTemplate(commonName, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return pemEncodeCertificate(der), pemEncodeECPrivateKey(key), nil
}

func generateSignedLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, usages []x509.ExtKeyUsage) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := leafTemplate(commonName, usages)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return pemEncodeCertificate(der), pemEncodeECPrivateKey(key), nil
}

func leafTemplate(commonName string, usages []x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
}

func serialNumber() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Errorf("generate serial number: %w", err))
	}
	return n
}

func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeECPrivateKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(fmt.Errorf("marshal private key: %w", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
