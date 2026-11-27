//go:build e2e

package e2e

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
)

// TestPathPrefixedGatewayEndToEnd guards the regression where a kubeconfig
// server URL with a path (https://gw.example.com/v1/proxy/<id>, as served by
// managed-cluster gateways) lost its path: kubegate kept only scheme and
// host, so the startup probe and every proxied request landed on the gateway
// root and 404ed.
//
// The real k3d cluster sits behind an in-process gateway that, like the real
// thing, serves only paths under the prefix, strips it, authenticates the
// caller by bearer token, and 404s everything else. The real kubegate binary
// is pointed at the gateway and driven by real kubectl.
func TestPathPrefixedGatewayEndToEnd(t *testing.T) {
	c := newCluster(t)

	const prefix = "/v1/proxy/abc123"
	const gwToken = "gateway-token"

	for _, ns := range []string{"app"} {
		if _, err := c.hostKubectl(t, "create", "namespace", ns); err != nil {
			t.Fatalf("creating namespace: %v", err)
		}
	}
	if _, err := c.hostKubectl(t, "create", "configmap", "app-config",
		"--from-literal=LOG_LEVEL=debug", "-n", "app"); err != nil {
		t.Fatalf("creating configmap: %v", err)
	}
	if _, err := c.hostKubectl(t, "create", "secret", "generic", "db",
		"--from-literal=password=hunter2", "-n", "app"); err != nil {
		t.Fatalf("creating secret: %v", err)
	}

	gwURL, seen := startPrefixGateway(t, c, prefix, gwToken)
	gw := &cluster{
		kubeconfig:  writeGatewayKubeconfig(t, gwURL+prefix, gwToken),
		contextName: "gw-ctx",
		binary:      c.binary,
	}

	// startProxy probes upstream at startup and waits for /version through
	// the proxy, so merely getting a ready proxy proves both paths carry the
	// prefix.
	p := gw.startProxy(t, "ro-nosecret")

	if out, err := p.kubectl(t, "get", "configmap", "app-config", "-n", "app", "-o", "name"); err != nil {
		t.Fatalf("get configmap through prefixed gateway: %v\n%s", err, out)
	} else if !strings.Contains(out, "configmap/app-config") {
		t.Errorf("unexpected output: %q", out)
	}
	if out, err := p.kubectl(t, "get", "pods", "-A", "--no-headers"); err != nil {
		t.Fatalf("get pods -A through prefixed gateway: %v\n%s", err, out)
	}
	// Discovery fan-out (/api, /apis, group versions) is what kubectl needs
	// to resolve resource names; it must carry the prefix too.
	if out, err := p.kubectl(t, "api-resources", "--verbs=list", "-o", "name"); err != nil {
		t.Fatalf("api-resources through prefixed gateway: %v\n%s", err, out)
	}

	// Policy is unaffected by the prefix: strict mode still denies secrets,
	// and the denied request must not reach the gateway.
	before := len(seen())
	if out, err := p.kubectl(t, "get", "secret", "db", "-n", "app"); err == nil {
		t.Errorf("secret read must be denied in ro-nosecret, got:\n%s", out)
	} else if strings.Contains(out, "hunter2") {
		t.Errorf("secret value leaked in denial output:\n%s", out)
	}
	for _, path := range seen()[before:] {
		if strings.Contains(path, "/secrets") {
			t.Errorf("denied secret request reached the gateway at %q", path)
		}
	}

	// Every request the gateway received -- probe included -- sat under the
	// prefix, with no doubled slashes.
	paths := seen()
	if len(paths) == 0 {
		t.Fatal("gateway saw no requests")
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, prefix+"/") || strings.Contains(path, "//") {
			t.Errorf("gateway received %q, want a path under %s/ without doubled slashes", path, prefix)
		}
	}
}

// startPrefixGateway fronts the cluster c with a TLS gateway on loopback. It
// returns the gateway's base URL (no prefix) and a recorder of every path it
// received, including ones it rejected.
func startPrefixGateway(t *testing.T, c *cluster, prefix, token string) (string, func() []string) {
	t.Helper()

	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: c.kubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: c.contextName},
	).ClientConfig()
	if err != nil {
		t.Fatalf("loading cluster kubeconfig: %v", err)
	}
	rt, err := rest.TransportFor(restCfg)
	if err != nil {
		t.Fatalf("building cluster transport: %v", err)
	}
	target, err := url.Parse(restCfg.Host)
	if err != nil {
		t.Fatal(err)
	}

	rp := &httputil.ReverseProxy{
		Transport:     rt,
		FlushInterval: -1,
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

// writeGatewayKubeconfig writes a host kubeconfig whose server URL carries a
// path prefix. Credentials are a bearer token, which client-go only attaches
// over https -- hence the TLS gateway and insecure-skip-tls-verify.
func writeGatewayKubeconfig(t *testing.T, server, token string) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["gw"] = &clientcmdapi.Cluster{Server: server, InsecureSkipTLSVerify: true}
	cfg.AuthInfos["u"] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts["gw-ctx"] = &clientcmdapi.Context{Cluster: "gw", AuthInfo: "u"}
	cfg.CurrentContext = "gw-ctx"
	p := filepath.Join(t.TempDir(), "gateway-kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, p); err != nil {
		t.Fatal(err)
	}
	return p
}
