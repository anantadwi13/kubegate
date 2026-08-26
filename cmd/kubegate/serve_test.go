package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFlagsRequiresCoreFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no args", []string{}, "context"},
		{"missing mode", []string{"--context", "c", "--listen", "127.0.0.1:8443"}, "mode"},
		{"missing listen", []string{"--context", "c", "--mode", "rw"}, "listen"},
		{"missing context", []string{"--mode", "rw", "--listen", "127.0.0.1:8443"}, "context"},
		{"bad mode", []string{"--context", "c", "--mode", "readonly", "--listen", "127.0.0.1:8443"}, "mode"},
		{"bad listen", []string{"--context", "c", "--mode", "rw", "--listen", "not-an-address"}, "listen"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseFlags(tc.args, io.Discard)
			if err == nil {
				if verr := c.validate(); verr != nil {
					err = verr
				}
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestParseFlagsAcceptsMinimalValidInvocation(t *testing.T) {
	c, err := parseFlags([]string{"--context", "prod", "--mode", "ro-nosecret", "--listen", "192.168.5.2:8443"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.contextName != "prod" || string(c.mode) != "ro-nosecret" || c.listen != "192.168.5.2:8443" {
		t.Errorf("parsed config wrong: %+v", c)
	}
	if len(c.namespaces) != 0 {
		t.Error("namespaces must default to empty, meaning unrestricted")
	}
}

func TestParseFlagsNamespaceList(t *testing.T) {
	c, err := parseFlags([]string{
		"--context", "p", "--mode", "rw", "--listen", "127.0.0.1:8443",
		"--namespace", "app, tools ,,default",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"app", "tools", "default"}
	if len(c.namespaces) != len(want) {
		t.Fatalf("namespaces = %v, want %v", c.namespaces, want)
	}
	for i := range want {
		if c.namespaces[i] != want[i] {
			t.Errorf("namespaces[%d] = %q, want %q", i, c.namespaces[i], want[i])
		}
	}
}

// The flag must fail loudly in a denylist mode. Silently ignoring it would
// let someone believe they had constrained a proxy that is wide open.
func TestValidateRejectsPolicyFlagInDenylistModes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ro-secret", "rw"} {
		c, err := parseFlags([]string{
			"--context", "p", "--mode", mode, "--listen", "127.0.0.1:8443", "--policy", p,
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		err = c.validate()
		if err == nil {
			t.Errorf("mode %s: --policy must be rejected", mode)
			continue
		}
		if !strings.Contains(err.Error(), "policy") {
			t.Errorf("mode %s: error should mention --policy: %v", mode, err)
		}
	}
}

func TestValidateAcceptsPolicyFlagInStrictMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	content := "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"widgets\"]\n    verbs: [\"get\"]\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := parseFlags([]string{
		"--context", "p", "--mode", "ro-nosecret", "--listen", "127.0.0.1:8443", "--policy", p,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(c.extraRules) != 1 {
		t.Errorf("extension rules not loaded: %+v", c.extraRules)
	}
}

func TestValidateRejectsInvalidPolicyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	// Wildcards defeat the fail-closed property the mode exists for.
	if err := os.WriteFile(p, []byte("rules:\n  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"get\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := parseFlags([]string{
		"--context", "p", "--mode", "ro-nosecret", "--listen", "127.0.0.1:8443", "--policy", p,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err == nil {
		t.Error("a wildcard policy file must be a startup failure")
	}
}

func TestDefaultsResolveUnderHome(t *testing.T) {
	c, err := parseFlags([]string{"--context", "p", "--mode", "rw", "--listen", "127.0.0.1:8443"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.tlsDir == "" {
		t.Error("--tls-dir must have a default")
	}
	if c.tokenFile == "" {
		t.Error("--token-file must have a default")
	}
	if !strings.Contains(c.tokenFile, "kubegate") {
		t.Errorf("token file default %q should live under a kubegate directory", c.tokenFile)
	}
}
