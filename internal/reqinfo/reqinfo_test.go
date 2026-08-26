package reqinfo

import (
	"net/http"
	"testing"
)

// These expectations were measured against k8s.io/apiserver v0.36.4. If a
// dependency bump changes any of them, the policy in internal/policy may no
// longer be sound -- read the spec section on parser behaviour before
// touching these numbers.
func TestParseAdversarialPaths(t *testing.T) {
	p := New()
	tests := []struct {
		name        string
		method      string
		url         string
		isResource  bool
		verb        string
		group       string
		resource    string
		subresource string
		namespace   string
		wantName    string
	}{
		{
			name: "namespaced list", method: "GET", url: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "list", resource: "pods", namespace: "app",
		},
		{
			name: "namespaced get", method: "GET", url: "/api/v1/namespaces/app/pods/web-1",
			isResource: true, verb: "get", resource: "pods", namespace: "app", wantName: "web-1",
		},
		{
			name: "watch via query param", method: "GET", url: "/api/v1/namespaces/app/pods?watch=true",
			isResource: true, verb: "watch", resource: "pods", namespace: "app",
		},
		{
			name: "watch via legacy path prefix", method: "GET", url: "/api/v1/watch/secrets",
			isResource: true, verb: "watch", resource: "secrets",
		},
		{
			name: "deletecollection", method: "DELETE", url: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "deletecollection", resource: "pods", namespace: "app",
		},
		{
			name: "grouped list", method: "GET", url: "/apis/apps/v1/namespaces/app/deployments",
			isResource: true, verb: "list", group: "apps", resource: "deployments", namespace: "app",
		},
		{
			name: "metrics group", method: "GET", url: "/apis/metrics.k8s.io/v1beta1/pods",
			isResource: true, verb: "list", group: "metrics.k8s.io", resource: "pods",
		},
		{
			name: "log subresource", method: "GET", url: "/api/v1/namespaces/app/pods/web-1/log",
			isResource: true, verb: "get", resource: "pods", subresource: "log", namespace: "app", wantName: "web-1",
		},
		{
			name: "exec subresource", method: "POST", url: "/api/v1/namespaces/app/pods/web-1/exec",
			isResource: true, verb: "create", resource: "pods", subresource: "exec", namespace: "app", wantName: "web-1",
		},
		{
			// The bypass. verb=proxy, and NO subresource at all.
			name: "legacy verb-via-path proxy", method: "GET", url: "/api/v1/proxy/namespaces/app/pods/web-1/foo",
			isResource: true, verb: "proxy", resource: "pods", namespace: "app", wantName: "web-1",
		},
		{
			name: "node proxy subresource", method: "GET", url: "/api/v1/nodes/node-1/proxy/metrics",
			isResource: true, verb: "get", resource: "nodes", subresource: "proxy", wantName: "node-1",
		},
		{
			name: "serviceaccount token", method: "POST", url: "/api/v1/namespaces/app/serviceaccounts/sa/token",
			isResource: true, verb: "create", resource: "serviceaccounts", subresource: "token", namespace: "app", wantName: "sa",
		},
		{
			// OPTIONS produces an EMPTY verb on a resource path.
			name: "options yields empty verb", method: "OPTIONS", url: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "", resource: "pods", namespace: "app",
		},
		{
			// Percent-decoding can only CREATE a subresource, never hide one.
			name: "percent-encoded separator", method: "GET", url: "/api/v1/namespaces/app/secrets/na%2Fme",
			isResource: true, verb: "get", resource: "secrets", subresource: "me", namespace: "app", wantName: "na",
		},
		{
			// A doubled slash fails the APIPrefixes check and arrives as a
			// NON-resource request, so the non-resource allowlist denies it.
			name: "double slash is non-resource", method: "GET", url: "//api/v1//secrets",
			isResource: false, verb: "get",
		},
		{
			name: "openapi is non-resource", method: "GET", url: "/openapi/v3",
			isResource: false, verb: "get",
		},
		{
			name: "group discovery is non-resource", method: "GET", url: "/apis/apps/v1",
			isResource: false, verb: "get",
		},
		{
			name: "metrics endpoint is non-resource", method: "GET", url: "/metrics",
			isResource: false, verb: "get",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			got, err := p.Parse(r)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.IsResourceRequest != tc.isResource {
				t.Errorf("IsResourceRequest = %v, want %v", got.IsResourceRequest, tc.isResource)
			}
			if got.Verb != tc.verb {
				t.Errorf("Verb = %q, want %q", got.Verb, tc.verb)
			}
			if got.APIGroup != tc.group {
				t.Errorf("APIGroup = %q, want %q", got.APIGroup, tc.group)
			}
			if got.Resource != tc.resource {
				t.Errorf("Resource = %q, want %q", got.Resource, tc.resource)
			}
			if got.Subresource != tc.subresource {
				t.Errorf("Subresource = %q, want %q", got.Subresource, tc.subresource)
			}
			if got.Namespace != tc.namespace {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tc.namespace)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
		})
	}
}

func TestParsePreservesPathForNonResource(t *testing.T) {
	p := New()
	r, _ := http.NewRequest("GET", "/debug/pprof/heap", nil)
	got, err := p.Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/debug/pprof/heap" {
		t.Errorf("Path = %q, want the raw path so the non-resource allowlist can match it exactly", got.Path)
	}
}
