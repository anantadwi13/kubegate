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

// TestFilterBodyPassesThroughAPIVersions guards the one deliberate
// exception to TestFilterBodyRejectsUnrecognizedKind below: the bare /api
// response (kind APIVersions) lists only server versions and address
// CIDRs, never a resource type, so it must keep passing through rather
// than tripping the fail-closed default -- a real apiserver serves exactly
// this body for GET /api in every mode.
func TestFilterBodyPassesThroughAPIVersions(t *testing.T) {
	body := []byte(`{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"127.0.0.1:1"}]}`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api", body)
	if err != nil {
		t.Fatalf("APIVersions must not be treated as unrecognized: %v", err)
	}
	if changed {
		t.Error("APIVersions has nothing to filter")
	}
	if string(out) != string(body) {
		t.Error("APIVersions body must be returned unchanged")
	}
}

// TestFilterBodyRejectsUnrecognizedKind guards the root cause behind the
// real Aggregated-Discovery fail-open (see filterAggregatedDiscoveryList's
// doc comment): FilterBody's default case used to return the ORIGINAL body
// unfiltered for any discovery "kind" it did not specifically recognize.
// That is exactly the shape that let APIGroupDiscoveryList leak "secrets"
// and every denied CRD before that one kind got its own case -- and it
// means the very next new discovery kind (from a future apiserver version,
// or a client requesting some other aggregated shape) reintroduces the same
// bypass. The default case must fail closed, not pass through, in
// ro-nosecret.
func TestFilterBodyRejectsUnrecognizedKind(t *testing.T) {
	body := []byte(`{"kind":"SomeFutureDiscoveryKind","apiVersion":"v1","resources":[
		{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["list"]}]}`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1", body)
	if err == nil {
		t.Fatal("an unrecognized discovery kind must be an error, not a passthrough")
	}
	if changed {
		t.Error("changed must be false alongside an error")
	}
	if strings.Contains(string(out), "secrets") {
		t.Error("secrets must never survive in the returned output")
	}
}

// TestFilterResourceListRejectsNonArrayResources guards a fail-open a
// reviewer demonstrated live: when "resources" is present but not an array
// (or is missing entirely), filterResourceList used to report "unchanged",
// and FilterBody then returned the ORIGINAL body verbatim — leaking
// "secrets" straight through ro-nosecret filtering. This must now be an
// error, never a passthrough.
func TestFilterResourceListRejectsNonArrayResources(t *testing.T) {
	body := []byte(`{
      "kind":"APIResourceList","groupVersion":"v1",
      "resources":{"secrets":{"namespaced":true,"kind":"Secret"}}
    }`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1", body)
	if err == nil {
		t.Fatal("a non-array \"resources\" field must be an error, not a passthrough")
	}
	if changed {
		t.Error("changed must be false alongside an error")
	}
	if strings.Contains(string(out), "secrets") {
		t.Error("secrets must never survive in the returned output")
	}

	body = []byte(`{"kind":"APIResourceList","groupVersion":"v1"}`)
	if _, _, err := FilterBody(engine(t, policy.ModeRONoSecret), "/api/v1", body); err == nil {
		t.Error("a missing \"resources\" field must be an error, not a passthrough")
	}
}

// TestFilterGroupListRejectsNonArrayGroups is the APIGroupList analog of
// TestFilterResourceListRejectsNonArrayResources.
func TestFilterGroupListRejectsNonArrayGroups(t *testing.T) {
	body := []byte(`{
      "kind":"APIGroupList",
      "groups":{"external-secrets.io":{"versions":[{"groupVersion":"external-secrets.io/v1beta1"}]}}
    }`)
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/apis", body)
	if err == nil {
		t.Fatal("a non-array \"groups\" field must be an error, not a passthrough")
	}
	if changed {
		t.Error("changed must be false alongside an error")
	}
	if strings.Contains(string(out), "external-secrets.io") {
		t.Error("the denied group must never survive in the returned output")
	}
}

// TestFilterResourceListWithNamespaceScopeStillShowsPermittedResources
// guards a regression a reviewer demonstrated live: filterResourceList used
// to probe with policy.Engine.Authorize, whose namespace-scoping stage
// treats an empty Namespace as ambiguous and denies it whenever
// --namespace scoping is active. That hid every namespaced resource from
// discovery even though a real, correctly-scoped request to it would
// succeed. The existence probe must ignore namespace scoping.
// aggregatedDiscoveryList is a trimmed version of the real
// APIGroupDiscoveryList shape kubectl 1.30+ requests via
// Accept: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,
// captured from a real k3s v1.30.0 apiserver's /apis response, plus a
// synthetic core-group entry (no "metadata.name") shaped like /api's
// response.
const aggregatedDiscoveryList = `{
  "kind":"APIGroupDiscoveryList","apiVersion":"apidiscovery.k8s.io/v2","metadata":{},
  "items":[
    {
      "metadata":{},
      "versions":[
        {
          "version":"v1",
          "resources":[
            {"resource":"pods","responseKind":{"group":"","version":"","kind":"Pod"},"scope":"Namespaced","verbs":["get","list","watch"],
             "subresources":[
               {"subresource":"log","responseKind":{"group":"","version":"","kind":"Pod"},"verbs":["get"]},
               {"subresource":"exec","responseKind":{"group":"","version":"","kind":"PodExecOptions"},"verbs":["create"]}
             ]},
            {"resource":"secrets","responseKind":{"group":"","version":"","kind":"Secret"},"scope":"Namespaced","verbs":["get","list","watch"]},
            {"resource":"configmaps","responseKind":{"group":"","version":"","kind":"ConfigMap"},"scope":"Namespaced","verbs":["get","list","watch"]}
          ],
          "freshness":"Current"
        }
      ]
    },
    {
      "metadata":{"name":"apps"},
      "versions":[
        {"version":"v1","resources":[
          {"resource":"deployments","responseKind":{"group":"","version":"","kind":"Deployment"},"scope":"Namespaced","verbs":["get","list","watch"]}
        ],"freshness":"Current"}
      ]
    },
    {
      "metadata":{"name":"rbac.authorization.k8s.io"},
      "versions":[
        {"version":"v1","resources":[
          {"resource":"roles","responseKind":{"group":"","version":"","kind":"Role"},"scope":"Namespaced","verbs":["get","list","watch"]}
        ],"freshness":"Current"}
      ]
    },
    {
      "metadata":{"name":"example.com"},
      "versions":[
        {"version":"v1","resources":[
          {"resource":"widgets","responseKind":{"group":"","version":"","kind":"Widget"},"scope":"Namespaced","verbs":["get","list","watch"]}
        ],"freshness":"Current"}
      ]
    }
  ]
}`

// TestFilterAggregatedDiscoveryListInStrictMode guards the fail-open a real
// kubectl (>=1.30) exposed against a real k3s >=1.30 apiserver: `kubectl
// api-resources` in strict mode requests this aggregated shape by default,
// and before filterAggregatedDiscoveryList existed, FilterBody's default
// case passed it through untouched, advertising "secrets" and every denied
// CRD even though direct access to them stayed correctly denied.
func TestFilterAggregatedDiscoveryListInStrictMode(t *testing.T) {
	out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/apis", []byte(aggregatedDiscoveryList))
	if err != nil {
		t.Fatalf("FilterBody: %v", err)
	}
	if !changed {
		t.Error("expected the aggregated discovery list to be filtered")
	}
	s := string(out)
	for _, want := range []string{"\"pods\"", "\"log\"", "\"configmaps\"", "\"deployments\""} {
		if !strings.Contains(s, want) {
			t.Errorf("%s must survive filtering:\n%s", want, s)
		}
	}
	for _, unwanted := range []string{"\"secrets\"", "\"exec\"", "\"widgets\""} {
		if strings.Contains(s, unwanted) {
			t.Errorf("%s must be filtered out:\n%s", unwanted, s)
		}
	}
	// rbac has no permitted resources in ro-nosecret and must be dropped
	// as a whole group, exactly like the flat APIGroupList case.
	if strings.Contains(s, "rbac.authorization.k8s.io") {
		t.Error("rbac group has no permitted resources and must be dropped")
	}
	if !strings.Contains(s, "\"apps\"") {
		t.Error("apps has a permitted resource and must survive")
	}

	var got struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(got.Items) == 0 {
		t.Fatal("filtering must not drop every group")
	}
}

func TestFilterAggregatedDiscoveryListPassesThroughInLooseModes(t *testing.T) {
	for _, m := range []policy.Mode{policy.ModeROSecret, policy.ModeRW} {
		out, changed, err := FilterBody(engine(t, m), "/apis", []byte(aggregatedDiscoveryList))
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

// TestFilterAggregatedDiscoveryListRejectsMalformedShapes is the aggregated
// analog of the flat-format tests guarding against a fail-open passthrough
// when a field is missing or the wrong type.
func TestFilterAggregatedDiscoveryListRejectsMalformedShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing items", `{"kind":"APIGroupDiscoveryList"}`},
		{"non-array items", `{"kind":"APIGroupDiscoveryList","items":{}}`},
		{"missing versions", `{"kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"}}]}`},
		{"non-array versions", `{"kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":{}}]}`},
		{"non-array resources", `{"kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":[{"version":"v1","resources":{}}]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, changed, err := FilterBody(engine(t, policy.ModeRONoSecret), "/apis", []byte(tc.body))
			if err == nil {
				t.Fatal("malformed aggregated discovery must be an error, not a passthrough")
			}
			if changed {
				t.Error("changed must be false alongside an error")
			}
			if strings.Contains(string(out), "secrets") {
				t.Error("secrets must never survive in the returned output")
			}
		})
	}
}

// TestFilterAggregatedDiscoveryListTreatsStaleGroupsAsEmpty guards a real
// failure found by driving actual kubectl through a real proxy against a
// real k3s apiserver: metrics.k8s.io/v1beta1 is advertised with
// "freshness":"Stale" and no "resources" field at all whenever the
// metrics-server backend has registered its APIService but has not yet
// answered a discovery call -- a normal, if narrow, startup window, not a
// malformed response. Treating the missing field as an error (as the flat
// APIResourceList format correctly does, since that endpoint has no
// legitimate reason to omit it) turned every kubectl command's up-front
// discovery walk into a hard failure during that window.
func TestFilterAggregatedDiscoveryListTreatsStaleGroupsAsEmpty(t *testing.T) {
	body := []byte(`{
      "kind":"APIGroupDiscoveryList","apiVersion":"apidiscovery.k8s.io/v2","metadata":{},
      "items":[
        {"metadata":{"name":"metrics.k8s.io"},"versions":[{"version":"v1beta1","freshness":"Stale"}]},
        {"metadata":{"name":"apps"},"versions":[{"version":"v1","resources":[
          {"resource":"deployments","responseKind":{"group":"","version":"","kind":"Deployment"},"scope":"Namespaced","verbs":["get","list","watch"]}
        ],"freshness":"Current"}]}
      ]
    }`)
	out, _, err := FilterBody(engine(t, policy.ModeRONoSecret), "/apis", body)
	if err != nil {
		t.Fatalf("a Stale group with no \"resources\" field must not be an error: %v", err)
	}
	if !strings.Contains(string(out), "metrics.k8s.io") {
		t.Error("the Stale group itself must survive untouched, not be dropped or error out")
	}
	if !strings.Contains(string(out), "deployments") {
		t.Error("filtering a Stale group must not affect other groups")
	}
}

func TestFilterResourceListWithNamespaceScopeStillShowsPermittedResources(t *testing.T) {
	e, err := policy.NewEngine(policy.Config{Mode: policy.ModeRONoSecret, Namespaces: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}
	out, changed, err := FilterBody(e, "/api/v1", []byte(coreV1Resources))
	if err != nil {
		t.Fatalf("FilterBody: %v", err)
	}
	if !changed {
		t.Error("expected secrets/pods-exec to still be filtered out")
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
	if !names["pods"] {
		t.Error("pods must still appear in discovery with --namespace scoping active")
	}
	if names["secrets"] {
		t.Error("secrets must still be filtered out")
	}
}
