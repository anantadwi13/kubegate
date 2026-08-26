//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/anantadwi13/kubegate/internal/audit"
	"github.com/anantadwi13/kubegate/internal/authn"
	"github.com/anantadwi13/kubegate/internal/policy"
	"github.com/anantadwi13/kubegate/internal/server"
	"github.com/anantadwi13/kubegate/internal/upstream"
)

var testEnv *envtest.Environment
var restCfg *rest.Config

func TestMain(m *testing.M) {
	testEnv = &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting envtest: %v\n"+
			"Did you run `make envtest` and set KUBEBUILDER_ASSETS?\n", err)
		os.Exit(1)
	}
	restCfg = cfg
	code := m.Run()
	_ = testEnv.Stop()
	os.Exit(code)
}

// writeKubeconfig writes a kubeconfig for the envtest apiserver using its
// admin client certificate.
func writeKubeconfig(t *testing.T) string {
	t.Helper()
	return writeKubeconfigWith(t, func(a *clientcmdapi.AuthInfo) {
		a.ClientCertificateData = restCfg.CertData
		a.ClientKeyData = restCfg.KeyData
	})
}

// writeKubeconfigWith lets a test supply a different auth mechanism, which is
// how the exec-plugin test swaps in a credential plugin.
func writeKubeconfigWith(t *testing.T, setAuth func(*clientcmdapi.AuthInfo)) string {
	t.Helper()
	auth := &clientcmdapi.AuthInfo{}
	setAuth(auth)

	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["envtest"] = &clientcmdapi.Cluster{
		Server:                   restCfg.Host,
		CertificateAuthorityData: restCfg.CAData,
	}
	cfg.AuthInfos["admin"] = auth
	cfg.Contexts["envtest-ctx"] = &clientcmdapi.Context{Cluster: "envtest", AuthInfo: "admin"}
	cfg.CurrentContext = "envtest-ctx"

	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, p); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}
	return p
}

// startProxy runs a kubegate listener against the envtest apiserver and
// returns its base URL, token, and an HTTP client that trusts it.
func startProxy(t *testing.T, mode policy.Mode, kubeconfigPath, contextName string) (string, string, *http.Client) {
	t.Helper()

	up, err := upstream.New(kubeconfigPath, contextName)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	if err := up.Probe(context.Background()); err != nil {
		t.Fatalf("upstream probe: %v", err)
	}

	e, err := policy.NewEngine(policy.Config{Mode: mode})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, caPEM, err := server.LoadOrCreateCert(dir, ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := server.LoadOrCreateToken(filepath.Join(dir, "token"), false)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authn.New(token)
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.NewHandler(server.Options{
		Upstream: up, Engine: e, Auth: auth,
		Audit: audit.NewLogger(io.Discard, mode, contextName),
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: h, TLSConfig: server.TLSConfig(cert)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not pin the proxy CA")
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	return "https://" + ln.Addr().String(), token, client
}

// get issues an authenticated GET through the proxy.
func get(t *testing.T, client *http.Client, base, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body
}

// probeOnly builds an upstream and probes it, returning the first error.
// Used to assert that broken credentials prevent startup.
func probeOnly(kubeconfigPath, contextName string) error {
	up, err := upstream.New(kubeconfigPath, contextName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return up.Probe(ctx)
}

func TestProxyServesRealAPIServer(t *testing.T) {
	kc := writeKubeconfig(t)
	base, token, client := startProxy(t, policy.ModeROSecret, kc, "envtest-ctx")

	code, body := get(t, client, base, token, "/api/v1/namespaces/default/pods")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", code, body)
	}
	if len(body) == 0 {
		t.Error("empty body")
	}
}

func TestProxyDeniesSecretsInStrictMode(t *testing.T) {
	kc := writeKubeconfig(t)
	base, token, client := startProxy(t, policy.ModeRONoSecret, kc, "envtest-ctx")

	if code, _ := get(t, client, base, token, "/api/v1/namespaces/default/secrets"); code != http.StatusForbidden {
		t.Errorf("secrets: status = %d, want 403", code)
	}
	if code, _ := get(t, client, base, token, "/api/v1/namespaces/default/configmaps"); code != http.StatusOK {
		t.Errorf("configmaps: status = %d, want 200", code)
	}
	// The bypass the spec records: legacy verb-via-path proxy.
	if code, _ := get(t, client, base, token, "/api/v1/proxy/namespaces/default/pods/x/foo"); code != http.StatusForbidden {
		t.Errorf("legacy proxy path: status = %d, want 403", code)
	}
	// Non-resource paths outside the allowlist.
	for _, p := range []string{"/metrics", "/logs", "/debug/pprof/"} {
		if code, _ := get(t, client, base, token, p); code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", p, code)
		}
	}
	// Discovery must keep working, or kubectl is unusable.
	for _, p := range []string{"/version", "/api", "/api/v1", "/apis", "/openapi/v3"} {
		if code, _ := get(t, client, base, token, p); code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p, code)
		}
	}
}
