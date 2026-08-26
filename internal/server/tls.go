package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	certFileName = "tls.crt"
	keyFileName  = "tls.key"
	certValidity = 10 * 365 * 24 * time.Hour
)

// LoadOrCreateCert returns the listener certificate, generating and
// persisting a self-signed one on first run.
//
// It must be stable across restarts: the guest pins this CA in its
// kubeconfig, so regenerating would silently break every client. Returns the
// certificate PEM for that pinning.
func LoadOrCreateCert(dir, listenAddr string, extraSANs []string) (*tls.Certificate, []byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("creating --tls-dir: %w", err)
	}
	// MkdirAll respects umask, so set the mode explicitly.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("securing --tls-dir: %w", err)
	}

	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("certificate exists but key is missing: %w", err)
		}
		// A stale key from a previous run (or external tampering) may be
		// more permissive than we'd ever write ourselves; tighten it rather
		// than silently trusting whatever mode is already on disk.
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return nil, nil, fmt.Errorf("securing persisted key: %w", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("loading persisted certificate: %w", err)
		}
		return &pair, certPEM, nil
	}

	certPEM, keyPEM, err := generateSelfSigned(listenAddr, extraSANs)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("writing key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("writing certificate: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return &pair, certPEM, nil
}

// generateSelfSigned builds a certificate that is its own trust anchor, with
// SANs covering every address the guest might dial. A missing SAN is the most
// likely cause of a TLS failure here, so the listen address is always
// included and hostnames and IPs are distinguished correctly.
func generateSelfSigned(listenAddr string, extraSANs []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	var ips []net.IP
	var dns []string
	addSAN := func(s string) {
		if s == "" {
			return
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			return
		}
		dns = append(dns, s)
	}

	host := listenAddr
	if h, _, splitErr := net.SplitHostPort(listenAddr); splitErr == nil {
		host = h
	}
	// A wildcard bind tells us nothing about how the guest will address us,
	// so cover loopback and let --tls-san carry the rest.
	if host == "" || host == "0.0.0.0" || host == "::" {
		addSAN("127.0.0.1")
		addSAN("::1")
		addSAN("localhost")
	} else {
		addSAN(host)
	}
	for _, s := range extraSANs {
		addSAN(s)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kubegate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Self-signed and self-anchoring: the guest pins this exact
		// certificate as its certificate-authority-data.
		IsCA:        true,
		IPAddresses: ips,
		DNSNames:    dns,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
