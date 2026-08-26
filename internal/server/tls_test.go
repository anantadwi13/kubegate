package server

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCertGeneratesAndPersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kubegate")

	cert, caPEM, err := LoadOrCreateCert(dir, "192.168.5.2:8443", nil)
	if err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("no certificate returned")
	}
	if len(caPEM) == 0 {
		t.Fatal("no CA PEM returned; the guest cannot pin without it")
	}

	// The IP the guest dials must be in the SANs or TLS verification fails.
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("caPEM is not valid PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	found := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.ParseIP("192.168.5.2")) {
			found = true
		}
	}
	if !found {
		t.Errorf("listen IP missing from SANs: %v", parsed.IPAddresses)
	}
	if !parsed.IsCA {
		t.Error("the certificate must be self-signed and usable as its own trust anchor")
	}

	// A second call must reuse, not regenerate: the guest's pinned CA has to
	// keep working across restarts.
	_, caPEM2, err := LoadOrCreateCert(dir, "192.168.5.2:8443", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(caPEM) != string(caPEM2) {
		t.Error("certificate was regenerated; a restart must not invalidate the guest kubeconfig")
	}
}

func TestLoadOrCreateCertPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kubegate")
	if _, _, err := LoadOrCreateCert(dir, "127.0.0.1:8443", nil); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 700", perm)
	}
	ki, err := os.Stat(filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}
}

func TestLoadOrCreateCertHonoursExtraSANs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kubegate")
	_, caPEM, err := LoadOrCreateCert(dir, "127.0.0.1:8443", []string{"host.lima.internal", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)

	dnsFound := false
	for _, d := range parsed.DNSNames {
		if d == "host.lima.internal" {
			dnsFound = true
		}
	}
	if !dnsFound {
		t.Errorf("DNS SAN missing: %v", parsed.DNSNames)
	}
	ipFound := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.ParseIP("10.0.0.5")) {
			ipFound = true
		}
	}
	if !ipFound {
		t.Errorf("extra IP SAN missing: %v", parsed.IPAddresses)
	}
}

func TestLoadOrCreateCertTightensStaleKeyPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kubegate")
	if _, _, err := LoadOrCreateCert(dir, "127.0.0.1:8443", nil); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "tls.key")
	// Simulate a stale key left over-permissive by a previous run or by
	// external tampering.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCert(dir, "127.0.0.1:8443", nil); err != nil {
		t.Fatal(err)
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := ki.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode after reuse = %o, want 600; a stale over-permissive key must not silently persist", perm)
	}
}

func TestLoadOrCreateCertHostnameListen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kubegate")
	_, caPEM, err := LoadOrCreateCert(dir, "host.example.com:8443", nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)
	if len(parsed.DNSNames) == 0 || parsed.DNSNames[0] != "host.example.com" {
		t.Errorf("a hostname listen address must become a DNS SAN: %v", parsed.DNSNames)
	}
}
