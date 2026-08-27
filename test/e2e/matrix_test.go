//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestModeMatrix drives real kubectl through a real proxy against a real
// cluster, one subtest per mode.
func TestModeMatrix(t *testing.T) {
	c := newCluster(t)
	c.seedFixtures(t)
	metricsReady := c.waitForMetrics(t)

	type expect struct {
		allowed bool
		args    []string
	}

	cases := map[string][]expect{
		"ro-nosecret": {
			{true, []string{"get", "pods", "-n", "app"}},
			{true, []string{"get", "configmap", "app-config", "-n", "app", "-o", "yaml"}},
			{false, []string{"get", "secrets", "-n", "app"}},
			{false, []string{"get", "widgets", "-n", "app"}},
			{false, []string{"get", "csr"}},
			{true, []string{"get", "deploy", "web", "-n", "app", "-o", "yaml"}},
			{true, []string{"get", "events", "-n", "app"}},
			{true, []string{"describe", "pod", "-n", "app", "-l", "app=web"}},
			{false, []string{"delete", "pod", "-n", "app", "-l", "app=web"}},
			{false, []string{"create", "configmap", "nope", "-n", "app", "--from-literal=a=b"}},
			{false, []string{"create", "token", "probe", "-n", "app"}},
			{true, []string{"get", "pods", "-A"}},
			{true, []string{"get", "nodes"}},
		},
		"ro-secret": {
			{true, []string{"get", "secrets", "-n", "app"}},
			{true, []string{"get", "widgets", "-n", "app"}},
			{true, []string{"get", "csr"}},
			{false, []string{"delete", "pod", "-n", "app", "-l", "app=web"}},
			{false, []string{"create", "token", "probe", "-n", "app"}},
			{true, []string{"get", "pods", "-A"}},
		},
		"rw": {
			{true, []string{"get", "secrets", "-n", "app"}},
			{true, []string{"get", "csr"}},
			{true, []string{"create", "configmap", "made-by-rw", "-n", "app", "--from-literal=a=b"}},
			{true, []string{"delete", "configmap", "made-by-rw", "-n", "app"}},
			{true, []string{"create", "clusterrolebinding", "rw-test", "--clusterrole=view", "--serviceaccount=app:probe"}},
			{false, []string{"create", "token", "probe", "-n", "app"}},
		},
	}

	for mode, expects := range cases {
		t.Run(mode, func(t *testing.T) {
			p := c.startProxy(t, mode)
			for _, e := range expects {
				name := strings.Join(e.args, " ")
				t.Run(name, func(t *testing.T) {
					out, err := p.kubectl(t, e.args...)
					if e.allowed && err != nil {
						t.Errorf("expected success, got error: %v\n%s", err, out)
					}
					if !e.allowed {
						if err == nil {
							t.Errorf("expected a denial, but the command succeeded:\n%s", out)
							return
						}
						// It must be denied by kubegate, not merely fail. A
						// resource kubegate's own discovery filtering hides
						// entirely (secrets, widgets, csr in ro-nosecret) never
						// reaches the proxy at all: kubectl's client-side
						// RESTMapper builds itself from the (correctly
						// filtered) discovery documents and fails locally with
						// "the server doesn't have a resource type" before
						// issuing any request. That is still kubegate policy
						// doing the denying -- these are real upstream
						// resource types, so the only reason the guest-side
						// kubectl cannot resolve them is that kubegate hid
						// them -- just surfaced earlier and more strongly than
						// a live 403.
						deniedByPolicy := strings.Contains(out, "kubegate") ||
							strings.Contains(out, "forbidden") ||
							strings.Contains(out, "doesn't have a resource type")
						if !deniedByPolicy {
							t.Errorf("denial did not come from kubegate policy: %v\n%s", err, out)
						}
					}
				})
			}

			// Interactive access is refused in every mode.
			t.Run("exec is refused", func(t *testing.T) {
				out, err := p.kubectl(t, "exec", "-n", "app", "deploy/web", "--", "true")
				if err == nil {
					t.Errorf("exec succeeded, which must never happen:\n%s", out)
				}
			})
			t.Run("port-forward is refused", func(t *testing.T) {
				out, err := p.kubectl(t, "port-forward", "-n", "app", "deploy/web", "18080:80", "--pod-running-timeout=10s")
				if err == nil {
					t.Errorf("port-forward succeeded, which must never happen:\n%s", out)
				}
			})

			if metricsReady {
				t.Run("top pods", func(t *testing.T) {
					if out, err := p.kubectl(t, "top", "pods", "-n", "app"); err != nil {
						t.Errorf("top pods failed: %v\n%s", err, out)
					}
				})
			}
		})
	}
}

// TestRedactionEndToEnd is the assertion that proves the strict mode's
// content promise against a manifest that really was applied with kubectl.
func TestRedactionEndToEnd(t *testing.T) {
	c := newCluster(t)
	c.seedFixtures(t)

	t.Run("strict mode strips the last-applied annotation", func(t *testing.T) {
		p := c.startProxy(t, "ro-nosecret")
		out, err := p.kubectl(t, "get", "deploy", "web", "-n", "app", "-o", "yaml")
		if err != nil {
			t.Fatalf("get deploy: %v\n%s", err, out)
		}
		if strings.Contains(out, "last-applied-configuration") {
			t.Error("last-applied annotation survived redaction")
		}
		if strings.Contains(out, "name: web") == false {
			t.Errorf("object was mangled:\n%s", out)
		}
	})

	t.Run("configmap data survives", func(t *testing.T) {
		p := c.startProxy(t, "ro-nosecret")
		out, err := p.kubectl(t, "get", "configmap", "app-config", "-n", "app", "-o", "yaml")
		if err != nil {
			t.Fatalf("get configmap: %v\n%s", err, out)
		}
		if !strings.Contains(out, "LOG_LEVEL") {
			t.Errorf("ConfigMap data was stripped, which would gut an allowed resource:\n%s", out)
		}
	})

	t.Run("loose mode keeps the annotation", func(t *testing.T) {
		p := c.startProxy(t, "ro-secret")
		out, err := p.kubectl(t, "get", "deploy", "web", "-n", "app", "-o", "yaml")
		if err != nil {
			t.Fatalf("get deploy: %v\n%s", err, out)
		}
		if !strings.Contains(out, "last-applied-configuration") {
			t.Error("ro-secret must not redact")
		}
	})

	t.Run("api-resources reflects the mode", func(t *testing.T) {
		strict := c.startProxy(t, "ro-nosecret")
		out, err := strict.kubectl(t, "api-resources", "--no-headers")
		if err != nil {
			t.Fatalf("api-resources: %v\n%s", err, out)
		}
		if strings.Contains(out, "secrets") {
			t.Errorf("strict mode advertised secrets:\n%s", out)
		}
		if !strings.Contains(out, "pods") {
			t.Errorf("strict mode dropped pods:\n%s", out)
		}
	})
}

func TestNamespaceScopeEndToEnd(t *testing.T) {
	c := newCluster(t)
	c.seedFixtures(t)
	p := c.startProxy(t, "ro-secret", "app")

	if out, err := p.kubectl(t, "get", "pods", "-n", "app"); err != nil {
		t.Errorf("in-scope namespace denied: %v\n%s", err, out)
	}
	if out, err := p.kubectl(t, "get", "pods", "-n", "other"); err == nil {
		t.Errorf("out-of-scope namespace allowed:\n%s", out)
	}
	if out, err := p.kubectl(t, "get", "pods", "-A"); err == nil {
		t.Errorf("cluster-wide collection allowed while scoped:\n%s", out)
	}
	// Cluster-scoped resources stay readable: --namespace narrows namespaced
	// access, it does not mean "nothing cluster-scoped".
	if out, err := p.kubectl(t, "get", "nodes"); err != nil {
		t.Errorf("cluster-scoped resource denied while scoped: %v\n%s", err, out)
	}
}

func TestWatchStreamsEndToEnd(t *testing.T) {
	c := newCluster(t)
	c.seedFixtures(t)
	p := c.startProxy(t, "ro-nosecret")

	// --watch-only with a timeout would hang forever if streaming were
	// buffered; a plain -w list-then-watch returns once the initial list is
	// printed under --request-timeout.
	out, err := p.kubectl(t, "get", "pods", "-n", "app", "-w", "--request-timeout=15s")
	if err != nil && !strings.Contains(out, "web") {
		t.Errorf("watch produced nothing: %v\n%s", err, out)
	}
	if !strings.Contains(out, "web") {
		t.Errorf("watch did not stream the initial list:\n%s", out)
	}
}

func TestAuthenticationEndToEnd(t *testing.T) {
	c := newCluster(t)
	p := c.startProxy(t, "ro-secret")

	// Rewrite the guest kubeconfig with a wrong token.
	raw, err := readFile(p.kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(raw, "token: ", "token: wrong-", 1)
	badPath := p.kubeconfig + ".bad"
	if err := writeFile(badPath, broken); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, 60*time.Second, "kubectl", "--kubeconfig", badPath, "get", "pods", "-n", "app"); err == nil {
		t.Errorf("a wrong token was accepted:\n%s", out)
	}
}
