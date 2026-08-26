package discovery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

func engine(t *testing.T, m policy.Mode) *policy.Engine {
	t.Helper()
	e, err := policy.NewEngine(policy.Config{Mode: m})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const coreV1Resources = `{
  "kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1",
  "resources":[
    {"name":"pods","namespaced":true,"kind":"Pod","verbs":["get","list","watch"]},
    {"name":"pods/log","namespaced":true,"kind":"Pod","verbs":["get"]},
    {"name":"pods/exec","namespaced":true,"kind":"PodExecOptions","verbs":["create"]},
    {"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list","watch"]},
    {"name":"configmaps","namespaced":true,"kind":"ConfigMap","verbs":["get","list","watch"]},
    {"name":"nodes","namespaced":false,"kind":"Node","verbs":["get","list","watch"]}
  ]
}`

func TestFilterResourceListInStrictMode(t *testing.T) {
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1", []byte(coreV1Resources))
	if err != nil {
		t.Fatalf("FilterBody: %v", err)
	}
	if !changed {
		t.Error("expected the list to be filtered")
	}
	var got struct {
		Resources []struct{ Name string } `json:"resources"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not a valid APIResourceList: %v", err)
	}
	names := map[string]bool{}
	for _, r := range got.Resources {
		names[r.Name] = true
	}
	for _, want := range []string{"pods", "pods/log", "configmaps", "nodes"} {
		if !names[want] {
			t.Errorf("%q must survive filtering", want)
		}
	}
	for _, unwanted := range []string{"secrets", "pods/exec"} {
		if names[unwanted] {
			t.Errorf("%q must be filtered out", unwanted)
		}
	}
}

func TestFilterResourceListPassesThroughInLooseModes(t *testing.T) {
	for _, m := range []policy.Mode{policy.ModeROSecret, policy.ModeRW} {
		out, changed, err := FilterBody(engine(t, m), "/api/v1", []byte(coreV1Resources))
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Errorf("mode %s must not filter discovery", m)
		}
		if !strings.Contains(string(out), "secrets") {
			t.Errorf("mode %s must keep secrets in discovery", m)
		}
	}
}

func TestFilterGroupListDropsEmptyGroups(t *testing.T) {
	body := []byte(`{
      "kind":"APIGroupList","apiVersion":"v1",
      "groups":[
        {"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},
        {"name":"rbac.authorization.k8s.io","versions":[{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}},
        {"name":"external-secrets.io","versions":[{"groupVersion":"external-secrets.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"external-secrets.io/v1beta1","version":"v1beta1"}}
      ]
    }`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/apis", body)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected groups to be dropped")
	}
	s := string(out)
	if !strings.Contains(s, "apps") {
		t.Error("apps has permitted resources and must survive")
	}
	if strings.Contains(s, "rbac.authorization.k8s.io") {
		t.Error("rbac group has no permitted resources and must be dropped")
	}
	if strings.Contains(s, "external-secrets.io") {
		t.Error("unknown CRD group must be dropped")
	}
}

func TestFilterBodyIgnoresNonDiscoveryPaths(t *testing.T) {
	body := []byte(`{"kind":"PodList","items":[]}`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1/namespaces/x/pods", body)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a non-discovery path must not be filtered here")
	}
	if string(out) != string(body) {
		t.Error("body must be returned unchanged")
	}
}

func TestFilterBodyMalformedIsAnError(t *testing.T) {
	if _, _, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1", []byte(`{"kind":`)); err == nil {
		t.Error("malformed discovery must be an error, not a passthrough")
	}
}
