//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// startGateway fronts the envtest apiserver the way a managed-cluster gateway
// does: it only serves paths under prefix (stripping it), authenticates the
// caller by bearer token, and 404s everything else. It returns its URL and a
// recorder of the raw paths it received.
func startGateway(t *testing.T, prefix, token string) (string, func() []string) {
	t.Helper()

	target, err := url.Parse(restCfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := rest.TransportFor(restCfg)
	if err != nil {
		t.Fatal(err)
	}
	rp := &httputil.ReverseProxy{
		Transport: rt,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, prefix)
			r.Out.URL.RawPath = ""
			r.Out.Header.Del("Authorization") // the gateway holds the cluster credential
		},
	}

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.NotFound(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func writeGatewayKubeconfig(t *testing.T, server, token string) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["gw"] = &clientcmdapi.Cluster{Server: server, InsecureSkipTLSVerify: true}
	cfg.AuthInfos["u"] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts["gw-ctx"] = &clientcmdapi.Context{Cluster: "gw", AuthInfo: "u"}
	cfg.CurrentContext = "gw-ctx"
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestProxyThroughPathPrefixedGateway is the regression for kubeconfigs whose
// server URL has a path: before the fix every request and the startup probe
// landed on the gateway root and 404ed.
func TestProxyThroughPathPrefixedGateway(t *testing.T) {
	const prefix = "/v1/proxy/abc123"
	for _, suffix := range []string{"", "/"} { // kubeconfigs in the wild have both
		t.Run("server url suffix "+suffix, func(t *testing.T) {
			gw, seen := startGateway(t, prefix, "gw-token")
			kc := writeGatewayKubeconfig(t, gw+prefix+suffix, "gw-token")

			// startProxy probes upstream and fails the test if it cannot.
			base, token, client := startProxy(t, policy.ModeROSecret, kc, "gw-ctx")

			for _, p := range []string{
				"/version", "/api", "/api/v1", "/apis",
				"/api/v1/namespaces/default/pods",
				"/api/v1/namespaces/default/configmaps?limit=1",
			} {
				if code, body := get(t, client, base, token, p); code != http.StatusOK {
					t.Errorf("%s: status = %d, body = %s", p, code, body)
				}
			}
			for _, p := range seen() {
				if !strings.HasPrefix(p, prefix+"/") || strings.Contains(p, "//") {
					t.Errorf("gateway received path %q, want it under %s/ without doubled slashes", p, prefix)
				}
			}
		})
	}
}

// Policy must still apply when a prefix is configured.
func TestPrefixedGatewayStillEnforcesPolicy(t *testing.T) {
	const prefix = "/v1/proxy/abc123"
	gw, seen := startGateway(t, prefix, "gw-token")
	kc := writeGatewayKubeconfig(t, gw+prefix, "gw-token")
	base, token, client := startProxy(t, policy.ModeRONoSecret, kc, "gw-ctx")

	before := len(seen())
	if code, _ := get(t, client, base, token, "/api/v1/namespaces/default/secrets"); code != http.StatusForbidden {
		t.Errorf("secrets: status = %d, want 403", code)
	}
	if code, _ := get(t, client, base, token, "/api/v1/namespaces/default/configmaps"); code != http.StatusOK {
		t.Errorf("configmaps: status = %d, want 200", code)
	}
	if got := len(seen()) - before; got != 1 {
		t.Errorf("gateway saw %d requests, want 1 (the denied one must not be forwarded)", got)
	}
}

// The startup probe must reach the gateway under the prefix, and still
// surface a rejected credential as a failure rather than a silent 404.
func TestProbeThroughPathPrefixedGateway(t *testing.T) {
	const prefix = "/v1/proxy/abc123"
	gw, seen := startGateway(t, prefix, "gw-token")

	if err := probeOnly(writeGatewayKubeconfig(t, gw+prefix, "gw-token"), "gw-ctx"); err != nil {
		t.Errorf("probe with correct prefix: %v", err)
	}
	// A 404 from the gateway root does not fail the probe, so assert on the
	// path the gateway actually received.
	if got := seen(); len(got) != 1 || got[0] != prefix+"/version" {
		t.Errorf("probe hit %v, want [%s/version]", got, prefix)
	}
	if err := probeOnly(writeGatewayKubeconfig(t, gw+prefix, "wrong-token"), "gw-ctx"); err == nil {
		t.Error("probe with a rejected token must fail")
	}
}
