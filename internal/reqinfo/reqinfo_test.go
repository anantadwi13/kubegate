package reqinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// roundTrip sends method+path through srv with a real http.Client and
// returns the *http.Request exactly as the server-side handler received it.
//
// This is not cosmetic. A test built by handing a bare path straight to
// http.NewRequest(method, path, nil) parses it via url.Parse -- client-side
// URL construction -- which reinterprets a leading "//" in a path as a
// network-path *authority* reference and silently strips it. A genuine
// inbound request is parsed server-side via url.ParseRequestURI (what
// net/http's request-line reader actually calls), which does not do that
// reinterpretation. Routing every case through a real httptest.Server with
// a real http.Client means each *http.Request handed to Parse in this file
// is exactly what production traffic would produce, adversarial paths
// included.
func roundTrip(t *testing.T, srv *httptest.Server, method, path string) *http.Request {
	t.Helper()
	var captured *http.Request
	done := make(chan struct{})
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		close(done)
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("building request for %s %s: %v", method, path, err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("round trip for %s %s: %v", method, path, err)
	}
	resp.Body.Close()
	<-done
	return captured
}

// These expectations were measured against k8s.io/apiserver v0.36.4 using a
// real server-side HTTP round trip (httptest.Server + http.Client), not a
// client-constructed *http.Request. See roundTrip above for why that
// distinction matters. If a dependency bump changes any of these numbers,
// the policy in internal/policy may no longer be sound -- read the spec
// section on parser behaviour before touching these numbers.
func TestParseAdversarialPaths(t *testing.T) {
	p := New()
	tests := []struct {
		name        string
		method      string
		path        string
		isResource  bool
		verb        string
		group       string
		apiVersion  string
		resource    string
		subresource string
		namespace   string
		wantName    string
	}{
		{
			name: "namespaced list", method: "GET", path: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "list", apiVersion: "v1", resource: "pods", namespace: "app",
		},
		{
			name: "namespaced get", method: "GET", path: "/api/v1/namespaces/app/pods/web-1",
			isResource: true, verb: "get", apiVersion: "v1", resource: "pods", namespace: "app", wantName: "web-1",
		},
		{
			name: "watch via query param", method: "GET", path: "/api/v1/namespaces/app/pods?watch=true",
			isResource: true, verb: "watch", apiVersion: "v1", resource: "pods", namespace: "app",
		},
		{
			name: "watch via legacy path prefix", method: "GET", path: "/api/v1/watch/secrets",
			isResource: true, verb: "watch", apiVersion: "v1", resource: "secrets",
		},
		{
			name: "deletecollection", method: "DELETE", path: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "deletecollection", apiVersion: "v1", resource: "pods", namespace: "app",
		},
		{
			name: "grouped list", method: "GET", path: "/apis/apps/v1/namespaces/app/deployments",
			isResource: true, verb: "list", group: "apps", apiVersion: "v1", resource: "deployments", namespace: "app",
		},
		{
			name: "metrics group", method: "GET", path: "/apis/metrics.k8s.io/v1beta1/pods",
			isResource: true, verb: "list", group: "metrics.k8s.io", apiVersion: "v1beta1", resource: "pods",
		},
		{
			name: "log subresource", method: "GET", path: "/api/v1/namespaces/app/pods/web-1/log",
			isResource: true, verb: "get", apiVersion: "v1", resource: "pods", subresource: "log", namespace: "app", wantName: "web-1",
		},
		{
			name: "exec subresource", method: "POST", path: "/api/v1/namespaces/app/pods/web-1/exec",
			isResource: true, verb: "create", apiVersion: "v1", resource: "pods", subresource: "exec", namespace: "app", wantName: "web-1",
		},
		{
			// The bypass. verb=proxy, and NO subresource at all.
			name: "legacy verb-via-path proxy", method: "GET", path: "/api/v1/proxy/namespaces/app/pods/web-1/foo",
			isResource: true, verb: "proxy", apiVersion: "v1", resource: "pods", namespace: "app", wantName: "web-1",
		},
		{
			name: "node proxy subresource", method: "GET", path: "/api/v1/nodes/node-1/proxy/metrics",
			isResource: true, verb: "get", apiVersion: "v1", resource: "nodes", subresource: "proxy", wantName: "node-1",
		},
		{
			name: "serviceaccount token", method: "POST", path: "/api/v1/namespaces/app/serviceaccounts/sa/token",
			isResource: true, verb: "create", apiVersion: "v1", resource: "serviceaccounts", subresource: "token", namespace: "app", wantName: "sa",
		},
		{
			// OPTIONS produces an EMPTY verb on a resource path.
			name: "options yields empty verb", method: "OPTIONS", path: "/api/v1/namespaces/app/pods",
			isResource: true, verb: "", apiVersion: "v1", resource: "pods", namespace: "app",
		},
		{
			// Percent-decoding can only CREATE a subresource, never hide one.
			name: "percent-encoded separator", method: "GET", path: "/api/v1/namespaces/app/secrets/na%2Fme",
			isResource: true, verb: "get", apiVersion: "v1", resource: "secrets", subresource: "me", namespace: "app", wantName: "na",
		},
		{
			// A genuine inbound request with a doubled leading slash is NOT
			// reinterpreted the way client-side url.Parse would reinterpret
			// it (see roundTrip's doc comment above). Server-side parsing
			// keeps the literal "//api/v1//secrets" path. That does not
			// match the shape the factory expects after the version
			// segment, so it comes back as a MALFORMED RESOURCE request:
			// IsResourceRequest is true, but Resource is empty and Name is
			// "secrets". It does NOT fall through to the non-resource
			// allowlist -- any policy relying on that would be bypassed.
			// It must instead be denied on the resource path, e.g. by a
			// rule that requires a non-empty Resource.
			name: "double slash produces malformed resource request", method: "GET", path: "//api/v1//secrets",
			isResource: true, verb: "get", apiVersion: "v1", resource: "", namespace: "", wantName: "secrets",
		},
		{
			name: "openapi is non-resource", method: "GET", path: "/openapi/v3",
			isResource: false, verb: "get",
		},
		{
			name: "group discovery is non-resource", method: "GET", path: "/apis/apps/v1",
			isResource: false, verb: "get",
		},
		{
			name: "metrics endpoint is non-resource", method: "GET", path: "/metrics",
			isResource: false, verb: "get",
		},
	}

	srv := httptest.NewServer(nil)
	defer srv.Close()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := roundTrip(t, srv, tc.method, tc.path)
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
			if got.APIVersion != tc.apiVersion {
				t.Errorf("APIVersion = %q, want %q", got.APIVersion, tc.apiVersion)
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
	srv := httptest.NewServer(nil)
	defer srv.Close()

	r := roundTrip(t, srv, "GET", "/debug/pprof/heap")
	got, err := p.Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/debug/pprof/heap" {
		t.Errorf("Path = %q, want the raw path so the non-resource allowlist can match it exactly", got.Path)
	}
}

// TestParseErrorOnUnparseablePath exercises the fail-closed error path: when
// RequestInfoFactory itself cannot determine kind/namespace from the URL, it
// returns an error, and Parse must propagate that error and hand back the
// full zero-value policy.Request -- never a partially-populated struct that
// might look permissive to a careless caller.
func TestParseErrorOnUnparseablePath(t *testing.T) {
	p := New()
	srv := httptest.NewServer(nil)
	defer srv.Close()

	paths := []string{"/api/v1/proxy", "/api/v1/watch"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			r := roundTrip(t, srv, "GET", path)
			got, err := p.Parse(r)
			if err == nil {
				t.Fatalf("Parse(%q): expected an error, got nil (result: %+v)", path, got)
			}
			if got != (policy.Request{}) {
				t.Errorf("Parse(%q) on error = %+v, want the zero-value policy.Request", path, got)
			}
		})
	}
}
