package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKubeconfig writes a kubeconfig with two contexts pointing at
// different servers, so context selection is actually observable.
func writeKubeconfig(t *testing.T, serverA, serverB string) string {
	t.Helper()
	content := `apiVersion: v1
kind: Config
clusters:
  - name: cluster-a
    cluster:
      server: ` + serverA + `
      insecure-skip-tls-verify: true
  - name: cluster-b
    cluster:
      server: ` + serverB + `
      insecure-skip-tls-verify: true
users:
  - name: user-a
    user:
      token: token-a
  - name: user-b
    user:
      token: token-b
contexts:
  - name: ctx-a
    context: {cluster: cluster-a, user: user-a}
  - name: ctx-b
    context: {cluster: cluster-b, user: user-b}
current-context: ctx-a
`
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewSelectsTheNamedContext(t *testing.T) {
	a := httptest.NewServer(http.NotFoundHandler())
	defer a.Close()
	b := httptest.NewServer(http.NotFoundHandler())
	defer b.Close()
	kc := writeKubeconfig(t, a.URL, b.URL)

	// The named context must win over current-context: the whole point is
	// that the host chooses the cluster, explicitly.
	u, err := New(kc, "ctx-b")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := u.BaseURL().String(); !strings.HasPrefix(b.URL, got) && got != b.URL {
		t.Errorf("BaseURL = %q, want %q", got, b.URL)
	}
	if u.ContextName() != "ctx-b" {
		t.Errorf("ContextName = %q, want ctx-b", u.ContextName())
	}
}

func TestNewRejectsUnknownContext(t *testing.T) {
	a := httptest.NewServer(http.NotFoundHandler())
	defer a.Close()
	kc := writeKubeconfig(t, a.URL, a.URL)
	_, err := New(kc, "does-not-exist")
	if err == nil {
		t.Fatal("an unknown context must be an error")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error should name the missing context: %v", err)
	}
}

func TestNewRequiresAContextName(t *testing.T) {
	a := httptest.NewServer(http.NotFoundHandler())
	defer a.Close()
	kc := writeKubeconfig(t, a.URL, a.URL)
	// Falling back to current-context would make the proxy's target depend
	// on ambient state; --context is required for a reason.
	if _, err := New(kc, ""); err == nil {
		t.Error("an empty context must be rejected rather than defaulted")
	}
}

func TestTransportInjectsCredentials(t *testing.T) {
	// client-go's rest.Config only attaches user credentials (bearer token,
	// client cert, exec/auth provider) when the target scheme is https --
	// it refuses to leak credentials over a plaintext connection
	// (rest.IsConfigTransportTLS). A plain httptest.NewServer therefore
	// never receives the Authorization header, regardless of upstream's own
	// correctness, so this test must exercise a TLS server; the
	// kubeconfig's insecure-skip-tls-verify accepts its self-signed cert.
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"31"}`))
	}))
	defer srv.Close()

	kc := writeKubeconfig(t, srv.URL, srv.URL)
	u, err := New(kc, "ctx-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if gotAuth != "Bearer token-a" {
		t.Errorf("upstream saw Authorization %q, want the host credential", gotAuth)
	}
}

func TestProbeFailsOnUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	u, err := New(writeKubeconfig(t, srv.URL, srv.URL), "ctx-a")
	if err != nil {
		t.Fatal(err)
	}
	err = u.Probe(context.Background())
	if err == nil {
		t.Fatal("a 401 from the cluster must fail the probe")
	}
	if !errors.Is(err, ErrCredentialsUnavailable) {
		t.Errorf("error %v must wrap ErrCredentialsUnavailable so main can print the login hint", err)
	}
}

func TestProbeFailsOnUnreachable(t *testing.T) {
	kc := writeKubeconfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	u, err := New(kc, "ctx-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Probe(context.Background()); err == nil {
		t.Error("an unreachable cluster must fail the probe")
	}
}
