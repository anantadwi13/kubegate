//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// k3sImage is pinned because k3d v5.5.0 defaults to k3s v1.26.4, which is
// old enough to miss current API shapes. This tag is verified to exist with
// an arm64 manifest.
//
// v1.31.14-k3s1 (the tag the design spec names) does not actually boot here:
// on a cgroup v2 host, k3d v5.5.0's bundled entrypoint runs a root-cgroup
// "evacuation" fix via `busybox xargs`, and every k3s image from
// v1.29.8-k3s1 through at least v1.32.6-k3s1 (checked, including the full
// v1.30/v1.31 lines) ships a busybox build with the xargs applet compiled
// out -- `busybox --list` omits it, though a standalone /bin/xargs binary
// is still present and works fine on its own. The fix script calls
// `busybox xargs` explicitly, so it fails with "xargs: applet not found",
// the write to cgroup.subtree_control then fails with EBUSY ("sed: write
// error") because the root cgroup was never evacuated, and the container
// exits(1) immediately and loops forever under restart-policy
// unless-stopped -- k3d reports this as "node ... is running=true in
// status=restarting". This is a real incompatibility between k3d v5.5.0
// and current k3s images, not anything about kubegate itself.
//
// v1.30.0-k3s1 happens to have been built with xargs still in busybox
// (confirmed via `busybox --list`) and boots cleanly on this host,
// verified end-to-end with `k3d cluster create --wait`. It is still well
// past v1.26.4 for the "current API shapes" concern the spec raised, and
// its apiserver advertises 62 api-resources here, comfortably above the
// >=40 sanity floor TestDiscoveryWalkClassification checks.
const k3sImage = "rancher/k3s:v1.30.0-k3s1"

const clusterName = "kubegate-e2e"

type cluster struct {
	kubeconfig  string
	contextName string
	binary      string
}

func run(t *testing.T, timeout time.Duration, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return out.String() + errb.String(), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, errb.String())
	}
	return out.String(), nil
}

// newCluster creates a k3d cluster, builds the binary, and registers cleanup.
func newCluster(t *testing.T) *cluster {
	t.Helper()
	if os.Getenv("KUBEGATE_E2E") != "1" {
		t.Skip("set KUBEGATE_E2E=1 to run end-to-end tests (requires Docker)")
	}
	for _, bin := range []string{"k3d", "kubectl", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found in PATH", bin)
		}
	}

	dir := t.TempDir()

	// Build the real binary: the e2e layer must exercise what ships.
	binary := filepath.Join(dir, "kubegate")
	if out, err := run(t, 5*time.Minute, "go", "build", "-o", binary, "../../cmd/kubegate"); err != nil {
		t.Fatalf("building kubegate: %v\n%s", err, out)
	}

	// A stale cluster from an interrupted run would poison this one.
	_, _ = run(t, 2*time.Minute, "k3d", "cluster", "delete", clusterName)

	if out, err := run(t, 10*time.Minute, "k3d", "cluster", "create", clusterName,
		"--agents", "1", "--image", k3sImage, "--wait"); err != nil {
		t.Fatalf("creating k3d cluster: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if _, err := run(t, 5*time.Minute, "k3d", "cluster", "delete", clusterName); err != nil {
			t.Logf("cluster cleanup failed: %v", err)
		}
	})

	kubeconfig := filepath.Join(dir, "host-kubeconfig")
	out, err := run(t, 2*time.Minute, "k3d", "kubeconfig", "get", clusterName)
	if err != nil {
		t.Fatalf("fetching kubeconfig: %v", err)
	}
	if err := os.WriteFile(kubeconfig, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cluster{kubeconfig: kubeconfig, contextName: "k3d-" + clusterName, binary: binary}
	c.waitForNodeReady(t)
	return c
}

// hostKubectl runs kubectl against the cluster directly, for fixture setup.
func (c *cluster) hostKubectl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--kubeconfig", c.kubeconfig, "--context", c.contextName}, args...)
	return run(t, 2*time.Minute, "kubectl", full...)
}

func (c *cluster) waitForNodeReady(t *testing.T) {
	t.Helper()
	if _, err := c.hostKubectl(t, "wait", "--for=condition=Ready", "nodes", "--all", "--timeout=180s"); err != nil {
		t.Fatalf("nodes never became ready: %v", err)
	}
}

// waitForMetrics polls the metrics API, which k3s bundles but which becomes
// ready some seconds after the cluster does. Polling beats racing it.
func (c *cluster) waitForMetrics(t *testing.T) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := c.hostKubectl(t, "get", "--raw", "/apis/metrics.k8s.io/v1beta1"); err == nil {
			if _, err := c.hostKubectl(t, "top", "pods", "-n", "kube-system"); err == nil {
				return true
			}
		}
		time.Sleep(5 * time.Second)
	}
	return false
}
