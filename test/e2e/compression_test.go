//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// TestLargeListSurvivesRealCompression guards a regression found live:
// `kubectl get pods -A` against a real cluster returned "kubegate could not
// process the cluster response and refused to forward it unchecked" once the
// response crossed the apiserver's gzip-compression threshold. kubectl's Go
// HTTP client sets its own Accept-Encoding on every request; forwarding that
// upstream unchanged (as kubegate used to) disables net/http's transparent
// decompression, so kubegate received raw gzip bytes labeled
// application/json, failed to JSON-decode them for redaction, and failed
// closed -- masking a perfectly good response as a generic 500. See the
// Rewrite comment in internal/server/server.go for the fix.
//
// TestModeMatrix's "get pods -A" case never caught this because the shared
// fixtures are too small to cross the apiserver's compression threshold.
// This test seeds enough real Pod objects that the real apiserver actually
// compresses the response, and fails loudly (not silently passes) if it ever
// stops doing so, since that would make the test meaningless.
func TestLargeListSurvivesRealCompression(t *testing.T) {
	c := newCluster(t)

	const ns = "filler"
	const podCount = 400
	if _, err := c.hostKubectl(t, "create", "namespace", ns); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}
	// The namespace controller creates the "default" ServiceAccount
	// asynchronously; a Pod applied before it exists is rejected outright
	// ("error looking up service account ... not found"), so wait for it.
	c.waitForDefaultServiceAccount(t, ns)
	c.seedFillerPods(t, ns, podCount)
	c.assertRealCompressionKicksIn(t, ns, podCount)

	p := c.startProxy(t, "ro-nosecret")
	out, err := p.kubectl(t, "get", "pods", "-A", "--no-headers")
	if err != nil {
		t.Fatalf("get pods -A on a compressed response: %v\n%s", err, out)
	}
	got := len(strings.Split(strings.TrimSpace(out), "\n"))
	if got < podCount {
		t.Errorf("got %d pods listed, want at least the %d filler pods seeded", got, podCount)
	}
}

// waitForDefaultServiceAccount polls until namespace ns has a "default"
// ServiceAccount. kubectl wait errors out immediately (rather than
// retrying) against a resource that does not exist yet, so this polls by
// hand instead, the same way waitForMetrics does in cluster_test.go.
func (c *cluster) waitForDefaultServiceAccount(t *testing.T, ns string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.hostKubectl(t, "get", "serviceaccount", "default", "-n", ns); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("namespace %s never got a default service account", ns)
}

// seedFillerPods creates podCount minimal Pod objects bound directly to a
// node name that does not exist, so they sit Pending forever without ever
// being scheduled or pulling an image -- only their JSON size in a List
// response matters here, not that they run.
func (c *cluster) seedFillerPods(t *testing.T, ns string, podCount int) {
	t.Helper()

	var manifest strings.Builder
	for i := 0; i < podCount; i++ {
		fmt.Fprintf(&manifest, `apiVersion: v1
kind: Pod
metadata:
  name: filler-%d
  namespace: %s
spec:
  nodeName: nonexistent-node
  containers:
    - name: c
      image: registry.k8s.io/pause:3.9
---
`, i, ns)
	}
	manifestPath := filepath.Join(t.TempDir(), "filler-pods.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hostKubectl(t, "apply", "-f", manifestPath); err != nil {
		t.Fatalf("creating %d filler pods: %v", podCount, err)
	}
}

// assertRealCompressionKicksIn fails the test outright (not skips) if the
// real apiserver does not actually compress a response this large: silently
// continuing would let TestLargeListSurvivesRealCompression pass without
// ever exercising the regression it exists to catch.
//
// It talks to the apiserver directly with the host's own credentials,
// bypassing kubegate entirely, and sets Accept-Encoding itself so
// net/http's transport does not manage decompression -- the same shape of
// request kubectl sends, and the same shape kubegate's Rewrite hook must
// strip before forwarding upstream.
func (c *cluster) assertRealCompressionKicksIn(t *testing.T, ns string, podCount int) {
	t.Helper()

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: c.kubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: c.contextName},
	).ClientConfig()
	if err != nil {
		t.Fatalf("building host client config: %v", err)
	}
	rt, err := rest.TransportFor(cfg)
	if err != nil {
		t.Fatalf("building host transport: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.Host, "/")+"/api/v1/namespaces/"+ns+"/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("probing host apiserver directly: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("apiserver did not compress a %d-pod list (Content-Encoding=%q); "+
			"this test no longer exercises the regression it guards -- seed more filler pods",
			podCount, resp.Header.Get("Content-Encoding"))
	}
}
