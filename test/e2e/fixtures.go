//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
