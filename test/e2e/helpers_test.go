//go:build e2e

package e2e

// Every e2e test in this package follows the same lifecycle, built from the
// pieces in this file:
//
//  1. newCluster(t)    - checks prerequisites, builds the real kubegate
//                         binary, creates a k3d cluster, and waits for it to
//                         be ready. Registers cluster teardown via
//                         t.Cleanup.
//  2. c.seedFixtures(t) - applies the namespaces/secrets/configmaps/
//                         deployment/CRD that the assertions in the other
//                         test files read.
//  3. c.startProxy(t, mode, ...) - launches kubegate against the cluster,
//                         captures the guest kubeconfig it prints, and waits
//                         for the proxy to answer requests. Registers proxy
//                         teardown via t.Cleanup (runs before cluster
//                         teardown, since Cleanup funcs run LIFO).
//  4. p.kubectl(t, ...) - drives real kubectl through the proxy using only
//                         the guest kubeconfig, which carries no cluster
//                         credential.
//
// Each top-level test creates and tears down its own cluster; they are not
// shared, so any test can run in isolation.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
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

	// Traefik, k3s's bundled default ingress controller, installs
	// asynchronously via an internal Helm job -- whether it finishes within
	// this test's window is a race against image-pull speed, which differs
	// by environment (it's consistently lost in one sandbox and consistently
	// won on GitHub Actions, adding 19 Traefik CRDs to the discovery walk
	// either way). It's irrelevant to what's under test here, so disable it
	// outright rather than let its presence be nondeterministic.
	if out, err := run(t, 10*time.Minute, "k3d", "cluster", "create", clusterName,
		"--agents", "1", "--image", k3sImage, "--wait",
		"--k3s-arg", "--disable=traefik@server:*"); err != nil {
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

// seedFixtures creates everything the assertion matrix reads.
func (c *cluster) seedFixtures(t *testing.T) {
	t.Helper()

	for _, ns := range []string{"app", "other"} {
		if _, err := c.hostKubectl(t, "create", "namespace", ns); err != nil {
			t.Fatalf("creating namespace %s: %v", ns, err)
		}
		if _, err := c.hostKubectl(t, "create", "secret", "generic", "db",
			"--from-literal=password=hunter2", "-n", ns); err != nil {
			t.Fatalf("creating secret in %s: %v", ns, err)
		}
		if _, err := c.hostKubectl(t, "create", "configmap", "app-config",
			"--from-literal=LOG_LEVEL=debug", "-n", ns); err != nil {
			t.Fatalf("creating configmap in %s: %v", ns, err)
		}
	}

	// kubectl apply, so a real last-applied-configuration annotation exists
	// carrying a literal env value. This is the leak redaction must close.
	manifest := filepath.Join(t.TempDir(), "deployment.yaml")
	if err := os.WriteFile(manifest, []byte(deploymentYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hostKubectl(t, "apply", "-f", manifest); err != nil {
		t.Fatalf("applying deployment: %v", err)
	}
	if _, err := c.hostKubectl(t, "wait", "--for=condition=Available",
		"deployment/web", "-n", "app", "--timeout=180s"); err != nil {
		t.Fatalf("deployment never became available: %v", err)
	}

	// A CRD standing in for a secret-bearing operator resource.
	crd := filepath.Join(t.TempDir(), "crd.yaml")
	if err := os.WriteFile(crd, []byte(widgetCRDYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hostKubectl(t, "apply", "-f", crd); err != nil {
		t.Fatalf("applying CRD: %v", err)
	}
	if _, err := c.hostKubectl(t, "wait", "--for=condition=Established",
		"crd/widgets.example.com", "--timeout=120s"); err != nil {
		t.Fatalf("CRD never established: %v", err)
	}
	instance := filepath.Join(t.TempDir(), "widget.yaml")
	if err := os.WriteFile(instance, []byte(widgetInstanceYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.hostKubectl(t, "apply", "-f", instance); err != nil {
		t.Fatalf("applying widget: %v", err)
	}

	if _, err := c.hostKubectl(t, "create", "serviceaccount", "probe", "-n", "app"); err != nil {
		t.Fatalf("creating serviceaccount: %v", err)
	}
}

const deploymentYAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  replicas: 1
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: registry.k8s.io/pause:3.9
          env:
            - name: DB_PASSWORD
              value: hunter2
`

const widgetCRDYAML = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    plural: widgets
    singular: widget
    kind: Widget
    listKind: WidgetList
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              x-kubernetes-preserve-unknown-fields: true
`

const widgetInstanceYAML = `apiVersion: example.com/v1
kind: Widget
metadata:
  name: w1
  namespace: app
spec:
  token: super-secret-value
`

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func writeFile(p, content string) error {
	return os.WriteFile(p, []byte(content), 0o600)
}

type proxy struct {
	kubeconfig string
	cmd        *exec.Cmd
	stderr     *bytes.Buffer
}

// freePort asks the kernel for an unused port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// startProxy launches the real binary and captures the guest kubeconfig it
// prints. Binding 127.0.0.1 is fine here: we are testing policy, not the
// VM-facing network path.
func (c *cluster) startProxy(t *testing.T, mode string, namespaces ...string) *proxy {
	t.Helper()

	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	args := []string{
		"serve",
		"--context", c.contextName,
		"--mode", mode,
		"--listen", addr,
		"--kubeconfig", c.kubeconfig,
		"--tls-dir", filepath.Join(dir, "tls"),
		"--token-file", filepath.Join(dir, "token"),
		"--audit-log", filepath.Join(dir, "audit.jsonl"),
	}
	if len(namespaces) > 0 {
		args = append(args, "--namespace", strings.Join(namespaces, ","))
	}

	cmd := exec.Command(c.binary, args...)
	stderr := &bytes.Buffer{}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = pw
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting kubegate: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = pw.Close()
		_ = pr.Close()
	})

	// Read the banner until the kubeconfig is complete, so we know the
	// listener is up and we have credentials to use.
	guestPath := filepath.Join(dir, "guest-kubeconfig")
	var captured bytes.Buffer
	scanner := bufio.NewScanner(pr)
	deadline := time.Now().Add(90 * time.Second)
	inConfig := false
	for scanner.Scan() {
		line := scanner.Text()
		stderr.WriteString(line + "\n")
		if strings.HasPrefix(line, "apiVersion: v1") {
			inConfig = true
		}
		if inConfig {
			captured.WriteString(line + "\n")
		}
		if strings.HasPrefix(line, "current-context:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kubegate never printed a kubeconfig:\n%s", stderr.String())
		}
	}
	if captured.Len() == 0 {
		t.Fatalf("no kubeconfig captured from kubegate:\n%s", stderr.String())
	}
	if err := os.WriteFile(guestPath, captured.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Drain the rest of the output so the process never blocks on a full pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := pr.Read(buf); err != nil {
				return
			}
		}
	}()

	p := &proxy{kubeconfig: guestPath, cmd: cmd, stderr: stderr}
	p.waitReady(t)
	return p
}

func (p *proxy) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := p.kubectl(t, "get", "--raw", "/version"); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("proxy never became ready:\n%s", p.stderr.String())
}

// kubectl drives the real kubectl through the proxy, using only the guest
// kubeconfig -- which contains no cluster credential.
func (p *proxy) kubectl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--kubeconfig", p.kubeconfig}, args...)
	return run(t, 90*time.Second, "kubectl", full...)
}
