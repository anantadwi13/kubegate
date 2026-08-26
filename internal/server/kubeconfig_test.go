package server

import (
	"encoding/base64"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestBannerEmitsUsableKubeconfig(t *testing.T) {
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
	const token = "kQ7Zt3xL9pR2vN8mB4cJ6yH1wS5dF0gA"

	out := Banner("https://192.168.5.2:8443", caPEM, token, "ro-nosecret", "prod-eks")

	if !strings.Contains(out, "ro-nosecret") {
		t.Error("banner must state the mode; it is the whole security posture")
	}
	if !strings.Contains(out, "prod-eks") {
		t.Error("banner must state the context")
	}

	// Extract the embedded kubeconfig and check it actually parses.
	start := strings.Index(out, "apiVersion: v1")
	if start < 0 {
		t.Fatalf("no kubeconfig found in banner:\n%s", out)
	}
	var cfg struct {
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
				CAData string `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
		Users []struct {
			Name string `json:"name"`
			User struct {
				Token string `json:"token"`
			} `json:"user"`
		} `json:"users"`
		CurrentContext string `json:"current-context"`
	}
	if err := yaml.Unmarshal([]byte(out[start:]), &cfg); err != nil {
		t.Fatalf("embedded kubeconfig does not parse: %v", err)
	}
	if len(cfg.Clusters) != 1 {
		t.Fatalf("want exactly 1 cluster entry so the guest cannot address anything else, got %d", len(cfg.Clusters))
	}
	if cfg.Clusters[0].Cluster.Server != "https://192.168.5.2:8443" {
		t.Errorf("server = %q", cfg.Clusters[0].Cluster.Server)
	}
	decoded, err := base64.StdEncoding.DecodeString(cfg.Clusters[0].Cluster.CAData)
	if err != nil {
		t.Fatalf("certificate-authority-data is not valid base64: %v", err)
	}
	if string(decoded) != string(caPEM) {
		t.Error("CA data does not round-trip")
	}
	if cfg.Users[0].User.Token != token {
		t.Error("token does not round-trip")
	}
	if cfg.CurrentContext == "" {
		t.Error("current-context must be set so kubectl works with no extra flags")
	}
}

func TestBannerCarriesNoClusterCredential(t *testing.T) {
	out := Banner("https://127.0.0.1:8443", []byte("ca"), "kQ7Zt3xL9pR2vN8mB4cJ6yH1wS5dF0gA", "rw", "ctx")
	for _, forbidden := range []string{"client-certificate", "client-key", "exec:", "auth-provider"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("guest kubeconfig must contain no cluster credential, found %q", forbidden)
		}
	}
}
