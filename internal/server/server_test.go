package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/anantadwi13/kubegate/internal/audit"
	"github.com/anantadwi13/kubegate/internal/authn"
	"github.com/anantadwi13/kubegate/internal/policy"
	"github.com/anantadwi13/kubegate/internal/upstream"
)

const testToken = "kQ7Zt3xL9pR2vN8mB4cJ6yH1wS5dF0gA"

// upstreamRecorder is a fake apiserver that records what reached it.
type upstreamRecorder struct {
	srv        *httptest.Server
	lastPath   string
	lastHeader http.Header
	lastMethod string
}

func newUpstream(t *testing.T, handler http.HandlerFunc) *upstreamRecorder {
	t.Helper()
	rec := &upstreamRecorder{}
	// client-go's rest.Config only attaches user credentials (bearer token,
	// client cert, exec/auth provider) when the target scheme is https --
	// it refuses to leak credentials over a plaintext connection
	// (rest.IsConfigTransportTLS). A plain httptest.NewServer would
	// therefore never receive the Authorization header, regardless of the
	// handler's own correctness, so the fake upstream must be TLS; the
	// kubeconfig's insecure-skip-tls-verify accepts its self-signed cert.
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.lastPath = r.URL.Path
		rec.lastHeader = r.Header.Clone()
		rec.lastMethod = r.Method
		handler(w, r)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func jsonUpstream(t *testing.T, body string) *upstreamRecorder {
	return newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// harness builds a handler wired to a fake upstream.
func harness(t *testing.T, mode policy.Mode, up *upstreamRecorder) http.Handler {
	t.Helper()

	kc := filepath.Join(t.TempDir(), "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n  - name: c\n    cluster:\n      server: " + up.srv.URL +
		"\n      insecure-skip-tls-verify: true\nusers:\n  - name: u\n    user:\n      token: upstream-token\n" +
		"contexts:\n  - name: ctx\n    context: {cluster: c, user: u}\ncurrent-context: ctx\n"
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	u, err := upstream.New(kc, "ctx")
	if err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(policy.Config{Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.New(testToken)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Options{
		Upstream: u,
		Engine:   e,
		Auth:     a,
		Audit:    audit.NewLogger(io.Discard, mode, "ctx"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func do(t *testing.T, h http.Handler, method, target string, withToken bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if withToken {
		r.Header.Set("Authorization", "Bearer "+testToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHandlerRequiresToken(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","items":[]}`)
	h := harness(t, policy.ModeROSecret, up)

	if rec := do(t, h, "GET", "/api/v1/namespaces/app/pods", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if up.lastPath != "" {
		t.Error("an unauthenticated request reached the upstream")
	}

	r := httptest.NewRequest("GET", "/api/v1/namespaces/app/pods", nil)
	r.Header.Set("Authorization", "Bearer wrongwrongwrongwrongwrongwrongwr")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: status = %d, want 401", rec.Code)
	}
	if up.lastPath != "" {
		t.Error("a request with a bad token reached the upstream")
	}
}

func TestHandlerForwardsAllowedRequest(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	h := harness(t, policy.ModeROSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/pods", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if up.lastPath != "/api/v1/namespaces/app/pods" {
		t.Errorf("upstream saw path %q", up.lastPath)
	}
	// The host credential must be injected, and only here.
	if got := up.lastHeader.Get("Authorization"); got != "Bearer upstream-token" {
		t.Errorf("upstream Authorization = %q, want the host credential", got)
	}
}

func TestHandlerDeniesByPolicy(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"SecretList","items":[]}`)
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/secrets", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if up.lastPath != "" {
		t.Error("a denied request reached the upstream; policy must gate before forwarding")
	}
	var st struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("denial body is not a Status: %v", err)
	}
	if st.Kind != "Status" {
		t.Errorf("kind = %q", st.Kind)
	}
	if !strings.Contains(st.Message, "kubegate") {
		t.Errorf("message must identify kubegate: %q", st.Message)
	}
}

func TestHandlerScrubsIdentityHeaders(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","items":[]}`)
	h := harness(t, policy.ModeROSecret, up)

	r := httptest.NewRequest("GET", "/api/v1/namespaces/app/pods", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Impersonate-User", "cluster-admin")
	r.Header.Set("Impersonate-Group", "system:masters")
	r.Header.Set("X-Remote-User", "attacker")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, k := range []string{"Impersonate-User", "Impersonate-Group", "X-Remote-User"} {
		if v := up.lastHeader.Get(k); v != "" {
			t.Errorf("upstream saw %s: %q -- impersonation was smuggled through", k, v)
		}
	}
}

func TestHandlerRejectsUpgrade(t *testing.T) {
	up := jsonUpstream(t, `{}`)
	h := harness(t, policy.ModeRW, up)

	r := httptest.NewRequest("GET", "/api/v1/namespaces/app/pods", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if up.lastPath != "" {
		t.Error("an upgrade request reached the upstream")
	}
}

func TestHandlerRedactsInStrictMode(t *testing.T) {
	body := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web",` +
		`"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"env\":\"hunter2\"}"}}}`
	up := jsonUpstream(t, body)
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/apis/apps/v1/namespaces/app/deployments/web", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Errorf("last-applied annotation leaked: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"web"`) {
		t.Errorf("object was mangled: %s", rec.Body.String())
	}
	// Content-Length must be corrected after rewriting, or clients hang
	// waiting for bytes that will never arrive.
	if cl := rec.Header().Get("Content-Length"); cl != "" && cl != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %s but body is %d bytes", cl, rec.Body.Len())
	}
}

func TestHandlerDoesNotRedactInLooseModes(t *testing.T) {
	body := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db"},"data":{"password":"aHVudGVyMg=="}}`
	up := jsonUpstream(t, body)
	h := harness(t, policy.ModeROSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/secrets/db", true)
	if !strings.Contains(rec.Body.String(), "aHVudGVyMg==") {
		t.Errorf("ro-secret must pass secret data through: %s", rec.Body.String())
	}
}

func TestHandlerStripsProtobufAcceptInStrictMode(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	h := harness(t, policy.ModeRONoSecret, up)

	r := httptest.NewRequest("GET", "/api/v1/namespaces/app/pods", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Accept", "application/vnd.kubernetes.protobuf, application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(up.lastHeader.Get("Accept"), "protobuf") {
		t.Errorf("protobuf must be stripped from Accept, got %q", up.lastHeader.Get("Accept"))
	}
	if !strings.Contains(up.lastHeader.Get("Accept"), "json") {
		t.Errorf("Accept must still request JSON, got %q", up.lastHeader.Get("Accept"))
	}
}

func TestHandlerRejectsProtobufOnlyInStrictMode(t *testing.T) {
	up := jsonUpstream(t, `{}`)
	h := harness(t, policy.ModeRONoSecret, up)

	r := httptest.NewRequest("GET", "/api/v1/namespaces/app/pods", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Accept", "application/vnd.kubernetes.protobuf")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNotAcceptable {
		t.Errorf("status = %d, want 406", rec.Code)
	}
}

func TestHandlerAbortsOnUnredactableBody(t *testing.T) {
	// Failing open here would silently void the mode's guarantee.
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind": not json`))
	})
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/pods", true)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "not json") {
		t.Error("unredactable bytes reached the client")
	}
}

func TestHandlerFiltersDiscoveryInStrictMode(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[
		{"name":"pods","namespaced":true,"kind":"Pod","verbs":["list"]},
		{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["list"]}]}`)
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/api/v1", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secrets") {
		t.Errorf("discovery must not advertise secrets in strict mode: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pods") {
		t.Errorf("discovery must still advertise pods: %s", rec.Body.String())
	}
}

func TestHandlerDeniesNonResourcePaths(t *testing.T) {
	up := jsonUpstream(t, `secret metrics`)
	h := harness(t, policy.ModeRW, up)

	for _, p := range []string{"/metrics", "/debug/pprof/heap", "/logs", "//api/v1//secrets"} {
		rec := do(t, h, "GET", p, true)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", p, rec.Code)
		}
	}
	if up.lastPath != "" {
		t.Error("a denied non-resource request reached the upstream")
	}
}

func TestHandlerCapsRequestBody(t *testing.T) {
	up := jsonUpstream(t, `{}`)
	h := harness(t, policy.ModeRW, up)

	big := strings.NewReader(strings.Repeat("x", MaxBodyBytes+1024))
	r := httptest.NewRequest("POST", "/api/v1/namespaces/app/configmaps", big)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestHandlerMapsUpstreamFailureToBadGateway(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n  - name: c\n    cluster:\n      server: http://127.0.0.1:1\n" +
		"users:\n  - name: u\n    user:\n      token: t\ncontexts:\n  - name: ctx\n    context: {cluster: c, user: u}\ncurrent-context: ctx\n"
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := upstream.New(kc, "ctx")
	e, _ := policy.NewEngine(policy.Config{Mode: policy.ModeROSecret})
	a, _ := authn.New(testToken)
	h, err := NewHandler(Options{Upstream: u, Engine: e, Auth: a, Audit: audit.NewLogger(io.Discard, policy.ModeROSecret, "ctx")})
	if err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "GET", "/api/v1/namespaces/app/pods", true)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	var st struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Kind != "Status" {
		t.Errorf("upstream failure must still render a Status: %s", rec.Body.String())
	}
}

// TestWriteProxyErrorMapping covers the status codes the spec requires.
// Collapsing these into one code would discard the only diagnostic the guest
// ever sees.
func TestWriteProxyErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"redaction failure", &errRedaction{errors.New("bad json")}, http.StatusInternalServerError},
		{"credentials unavailable", fmt.Errorf("wrapped: %w", upstream.ErrCredentialsUnavailable), http.StatusServiceUnavailable},
		{"timeout", &net.DNSError{IsTimeout: true}, http.StatusGatewayTimeout},
		{"anything else", errors.New("connection refused"), http.StatusBadGateway},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeProxyError(rec, httptest.NewRequest("GET", "/api/v1/pods", nil), tc.err)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			var st struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Kind != "Status" {
				t.Errorf("body must be a Status: %s", rec.Body.String())
			}
			// No error path may leak upstream detail.
			for _, leak := range []string{"bad json", "connection refused"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Errorf("body leaks internal detail %q: %s", leak, rec.Body.String())
				}
			}
		})
	}
}

func TestTLSConfigOffersHTTP11Only(t *testing.T) {
	// Connection: Upgrade has no HTTP/2 equivalent, so a defense-in-depth
	// layer that silently stops applying is worse than none.
	cfg := TLSConfig(&tls.Certificate{})
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want exactly [http/1.1]", cfg.NextProtos)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestHandlerPreservesQueryString(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	h := harness(t, policy.ModeROSecret, up)

	var seen *url.URL
	// Re-wrap so we can inspect the raw query the upstream received.
	up.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL
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
	if seen.Query().Get("labelSelector") != "app=web" || seen.Query().Get("limit") != "5" {
		t.Errorf("query not preserved: %q", seen.RawQuery)
	}
}

// TestAuditRedactedReflectsActualChange guards against the audit log's
// "redacted" field being derived from the mode alone (e.g. "strict mode and
// allowed, so call it redacted"). That would claim a change happened even on
// responses redact.Body left untouched. The field must instead reflect what
// redact.Body / discovery.FilterBody actually reported.
func TestAuditRedactedReflectsActualChange(t *testing.T) {
	auditLine := func(t *testing.T, up *upstreamRecorder, path string) map[string]any {
		t.Helper()
		kc := filepath.Join(t.TempDir(), "kubeconfig")
		content := "apiVersion: v1\nkind: Config\nclusters:\n  - name: c\n    cluster:\n      server: " + up.srv.URL +
			"\n      insecure-skip-tls-verify: true\nusers:\n  - name: u\n    user:\n      token: upstream-token\n" +
			"contexts:\n  - name: ctx\n    context: {cluster: c, user: u}\ncurrent-context: ctx\n"
		if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		u, err := upstream.New(kc, "ctx")
		if err != nil {
			t.Fatal(err)
		}
		e, err := policy.NewEngine(policy.Config{Mode: policy.ModeRONoSecret})
		if err != nil {
			t.Fatal(err)
		}
		a, err := authn.New(testToken)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		h, err := NewHandler(Options{
			Upstream: u,
			Engine:   e,
			Auth:     a,
			Audit:    audit.NewLogger(&buf, policy.ModeRONoSecret, "ctx"),
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := do(t, h, "GET", path, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var line map[string]any
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("audit line is not valid JSON: %v (%q)", err, buf.String())
		}
		return line
	}

	t.Run("body actually rewritten", func(t *testing.T) {
		body := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web",` +
			`"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}}`
		up := jsonUpstream(t, body)
		line := auditLine(t, up, "/apis/apps/v1/namespaces/app/deployments/web")
		if r, _ := line["redacted"].(bool); !r {
			t.Errorf("redacted = %v, want true: the last-applied annotation was actually stripped", line["redacted"])
		}
	})

	t.Run("body already clean", func(t *testing.T) {
		body := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cfg"},"data":{"k":"v"}}`
		up := jsonUpstream(t, body)
		line := auditLine(t, up, "/api/v1/namespaces/app/configmaps/cfg")
		if r, _ := line["redacted"].(bool); r {
			t.Errorf("redacted = %v, want false: nothing in this body needed redaction", line["redacted"])
		}
	})
}
