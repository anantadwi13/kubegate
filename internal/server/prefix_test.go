package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// Clusters fronted by a gateway (https://gw.example.com/v1/proxy/<id>) carry
// a path in the kubeconfig server URL. These tests pin that the prefix is
// applied to every outbound request and only to the outbound request: policy
// still judges the path the guest sent.

func TestHandlerPreservesUpstreamPathPrefix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		target string
		want   string
	}{
		{"no prefix is unchanged", "", "/api/v1/namespaces/app/pods", "/api/v1/namespaces/app/pods"},
		{"bare slash is unchanged", "/", "/api/v1/namespaces/app/pods", "/api/v1/namespaces/app/pods"},
		{"single segment", "/gw", "/api/v1/namespaces/app/pods", "/gw/api/v1/namespaces/app/pods"},
		{"multi segment", "/v1/proxy/abc123", "/api/v1/namespaces/app/pods", "/v1/proxy/abc123/api/v1/namespaces/app/pods"},
		{"trailing slash does not double", "/v1/proxy/abc123/", "/api/v1/namespaces/app/pods", "/v1/proxy/abc123/api/v1/namespaces/app/pods"},
		{"discovery root", "/v1/proxy/abc123", "/api", "/v1/proxy/abc123/api"},
		{"apis group path", "/v1/proxy/abc123", "/apis/apps/v1/namespaces/app/deployments", "/v1/proxy/abc123/apis/apps/v1/namespaces/app/deployments"},
		{"version non-resource", "/v1/proxy/abc123", "/version", "/v1/proxy/abc123/version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
			h := harnessAt(t, policy.ModeROSecret, up.srv.URL+tc.prefix)

			rec := do(t, h, "GET", tc.target, true)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if up.lastPath != tc.want {
				t.Errorf("upstream saw path %q, want %q", up.lastPath, tc.want)
			}
		})
	}
}

func TestHandlerPrefixKeepsQueryAndCredentials(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	h := harnessAt(t, policy.ModeROSecret, up.srv.URL+"/v1/proxy/abc123")

	var seen *url.URL
	up.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL
		up.lastHeader = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":[]}`))
	})

	rec := do(t, h, "GET", "/api/v1/namespaces/app/pods?labelSelector=app%3Dweb&limit=5", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if seen == nil {
		t.Fatal("upstream never saw the request")
	}
	if seen.Path != "/v1/proxy/abc123/api/v1/namespaces/app/pods" {
		t.Errorf("path = %q", seen.Path)
	}
	if seen.Query().Get("labelSelector") != "app=web" || seen.Query().Get("limit") != "5" {
		t.Errorf("query not preserved: %q", seen.RawQuery)
	}
	if got := up.lastHeader.Get("Authorization"); got != "Bearer upstream-token" {
		t.Errorf("upstream Authorization = %q, want the host credential", got)
	}
}

// The prefix is an upstream routing detail. Policy must judge the path the
// guest sent: a guest that includes the prefix itself must not be treated as
// asking for a resource path, and a denied request must never reach the
// gateway whether or not a prefix is configured.
func TestHandlerPrefixDoesNotAffectPolicy(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"SecretList","items":[]}`)
	h := harnessAt(t, policy.ModeRONoSecret, up.srv.URL+"/v1/proxy/abc123")

	for _, target := range []string{
		"/api/v1/namespaces/app/secrets",
		"/api/v1/namespaces/app/pods/p/exec",
		"/v1/proxy/abc123/api/v1/namespaces/app/pods", // guest echoing the prefix
		"/metrics",
	} {
		if rec := do(t, h, "GET", target, true); rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, rec.Code)
		}
	}
	if up.lastPath != "" {
		t.Errorf("a denied request reached the upstream at %q", up.lastPath)
	}
}

// A guest-supplied path must be appended after the prefix and never be able
// to replace or climb out of it.
func TestHandlerPrefixCannotBeEscapedByGuestPath(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	h := harnessAt(t, policy.ModeROSecret, up.srv.URL+"/v1/proxy/abc123")

	for _, target := range []string{
		"/api/v1/namespaces/app/pods/../../../../../other",
		"/api/v1/namespaces/app/pods/%2e%2e/%2e%2e",
	} {
		up.lastPath = ""
		_ = do(t, h, "GET", target, true)
		if up.lastPath != "" && !hasPrefix(up.lastPath, "/v1/proxy/abc123/") {
			t.Errorf("%s: upstream saw %q outside the gateway prefix", target, up.lastPath)
		}
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
