package server

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// negotiatingUpstream behaves like a real content-negotiating apiserver: it
// serves yamlBody as application/yaml whenever the incoming Accept header
// asks for YAML and does not also accept JSON, and jsonBody as
// application/json otherwise. A fake upstream that always answers with
// application/json (as jsonUpstream does) can never reproduce the
// Accept-header bypass this proxy must close, because the bug is entirely
// about what the upstream is asked for.
func negotiatingUpstream(t *testing.T, jsonBody, yamlBody string) *upstreamRecorder {
	return newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		accept := strings.ToLower(r.Header.Get("Accept"))
		if strings.Contains(accept, "yaml") && !strings.Contains(accept, "json") {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write([]byte(yamlBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonBody))
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

// TestNegotiateJSONAllowlistsJSONFamily locks down negotiateJSON as an
// ALLOWLIST rather than a denylist. The prior version stripped only
// protobuf and forwarded every other requested media type -- including
// application/yaml -- unchanged, which routed responses straight around the
// redaction/discovery-filtering pipeline (modifyResponse only transforms
// JSON bodies). Only entries whose base media type is application/json may
// survive; everything else, known or not, must be dropped.
func TestNegotiateJSONAllowlistsJSONFamily(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		wantOK   bool
		wantKept string // substring that must survive
		wantGone string // substring that must not survive
	}{
		{"empty defaults to json", "", true, "application/json", ""},
		{"protobuf only is rejected", "application/vnd.kubernetes.protobuf", false, "", ""},
		{"yaml only is rejected", "application/yaml", false, "", ""},
		{"yaml dropped, json kept", "application/yaml, application/json", true, "application/json", "yaml"},
		{"protobuf dropped, json kept", "application/vnd.kubernetes.protobuf, application/json", true, "application/json", "protobuf"},
		{"table params survive", "application/json;as=Table;g=meta.k8s.io;v=v1, application/json", true, "as=Table", ""},
		{"bare wildcard forced to json", "*/*", true, "application/json", "*/*"},
		{"unknown type is rejected", "text/plain", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.accept != "" {
				h.Set("Accept", tc.accept)
			}
			ok := negotiateJSON(h)
			if ok != tc.wantOK {
				t.Fatalf("negotiateJSON(%q) ok = %v, want %v (Accept now %q)", tc.accept, ok, tc.wantOK, h.Get("Accept"))
			}
			if tc.wantKept != "" && !strings.Contains(h.Get("Accept"), tc.wantKept) {
				t.Errorf("Accept = %q, want it to contain %q", h.Get("Accept"), tc.wantKept)
			}
			if tc.wantGone != "" && strings.Contains(strings.ToLower(h.Get("Accept")), tc.wantGone) {
				t.Errorf("Accept = %q, must not contain %q", h.Get("Accept"), tc.wantGone)
			}
		})
	}
}

// TestHandlerAcceptYAMLCannotLeakRedactedContent is the end-to-end
// regression for the Accept-header bypass: a client asking for YAML must
// never receive the unredacted representation of an object ro-nosecret
// would otherwise redact.
func TestHandlerAcceptYAMLCannotLeakRedactedContent(t *testing.T) {
	jsonBody := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web",` +
		`"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"env\":\"hunter2\"}"}}}`
	// A real apiserver would happily serve the identical secret-bearing
	// content as YAML; this fake reproduces that so the test actually
	// exercises the bypass rather than an upstream that never leaks.
	yamlBody := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  annotations:\n" +
		"    kubectl.kubernetes.io/last-applied-configuration: '{\"env\":\"hunter2\"}'\n"

	t.Run("pure yaml Accept is rejected outright", func(t *testing.T) {
		up := negotiatingUpstream(t, jsonBody, yamlBody)
		h := harness(t, policy.ModeRONoSecret, up)

		r := httptest.NewRequest("GET", "/apis/apps/v1/namespaces/app/deployments/web", nil)
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Accept", "application/yaml")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		if strings.Contains(rec.Body.String(), "hunter2") {
			t.Fatalf("secret leaked via Accept: application/yaml: status=%d body=%s", rec.Code, rec.Body.String())
		}
		if rec.Code == http.StatusOK {
			t.Errorf("a pure application/yaml Accept must not be silently satisfied with 200: body=%s", rec.Body.String())
		}
	})

	t.Run("yaml with json fallback still gets redacted", func(t *testing.T) {
		up := negotiatingUpstream(t, jsonBody, yamlBody)
		h := harness(t, policy.ModeRONoSecret, up)

		r := httptest.NewRequest("GET", "/apis/apps/v1/namespaces/app/deployments/web", nil)
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Accept", "application/yaml, application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		if strings.Contains(rec.Body.String(), "hunter2") {
			t.Fatalf("secret leaked via Accept: application/yaml, application/json: status=%d body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(up.lastHeader.Get("Accept"), "yaml") {
			t.Errorf("upstream must not have been asked for yaml: %q", up.lastHeader.Get("Accept"))
		}
		if rec.Code != http.StatusOK {
			t.Errorf("json was still on offer; the request should have succeeded, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

// TestHandlerAcceptYAMLCannotBypassDiscoveryFiltering is the discovery-path
// analog: a doubly-defended request for YAML discovery must not surface
// resources the mode's allowlist would otherwise hide.
func TestHandlerAcceptYAMLCannotBypassDiscoveryFiltering(t *testing.T) {
	jsonBody := `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[
		{"name":"pods","namespaced":true,"kind":"Pod","verbs":["list"]},
		{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["list"]}]}`
	yamlBody := "kind: APIResourceList\napiVersion: v1\ngroupVersion: v1\nresources:\n" +
		"- {name: pods, namespaced: true, kind: Pod, verbs: [list]}\n" +
		"- {name: secrets, namespaced: true, kind: Secret, verbs: [list]}\n"

	up := negotiatingUpstream(t, jsonBody, yamlBody)
	h := harness(t, policy.ModeRONoSecret, up)

	r := httptest.NewRequest("GET", "/api/v1", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Accept", "application/yaml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if strings.Contains(rec.Body.String(), "secrets") {
		t.Fatalf("discovery leaked secrets via Accept: application/yaml: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusOK {
		t.Errorf("a pure application/yaml Accept for discovery must not be silently satisfied with 200: body=%s", rec.Body.String())
	}
}

// TestHandlerFailsClosedOnUnexpectedNonJSONInStrictMode is the defense-in-
// depth half of the Accept-header fix: even though negotiateJSON forces a
// JSON-family Accept in ro-nosecret, modifyResponse must not silently
// forward a response anyway if it somehow comes back non-JSON (upstream
// ignored the header, or a future gap in the rewrite).
func TestHandlerFailsClosedOnUnexpectedNonJSONInStrictMode(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("raw-unfiltered-hunter2"))
	})
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/configmaps/cfg", true)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (fail closed)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("unexpected non-JSON bytes must never reach the client")
	}
}

// TestHandlerAllowsNonJSONPodLogInStrictMode guards against the hardening
// above over-reaching: pods/log is unconditionally readable in every mode
// (see spec §2) and the kubelet ignores content negotiation for it,
// answering with plain text regardless of Accept. That must keep working in
// ro-nosecret.
func TestHandlerAllowsNonJSONPodLogInStrictMode(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("log line one\nlog line two\n"))
	})
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/api/v1/namespaces/app/pods/web/log", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; pods/log must stay readable in ro-nosecret: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "log line one") {
		t.Errorf("log body was mangled: %s", rec.Body.String())
	}
}

// TestHandlerAllowsNonJSONOpenAPIInStrictMode guards the hardening in
// TestHandlerFailsClosedOnUnexpectedNonJSONInStrictMode against
// over-reaching: a real apiserver's /openapi/v3 root index answers
// text/plain even when JSON was explicitly requested (observed against a
// real envtest apiserver), and /openapi/v2, /openapi/v3/*, and /version are
// never filtered in any mode regardless of content type (see README "What
// it does not provide"). None of that may become a 500 in ro-nosecret.
func TestHandlerAllowsNonJSONOpenAPIInStrictMode(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(`{"paths":{}}`))
	})
	h := harness(t, policy.ModeRONoSecret, up)

	rec := do(t, h, "GET", "/openapi/v3", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; /openapi/v3 is never filtered and may legitimately be non-JSON: %s", rec.Code, rec.Body.String())
	}
}

// TestHandlerPassesThroughNonOKDiscoveryResponses guards a regression found
// by running the full e2e suite against a real k3d cluster after the fixes
// above landed: under API Priority and Fairness, a discovery-path request
// can legitimately come back non-200 (observed: a rejected request
// answered non-JSON) -- and a real apiserver error response is always kind
// "Status", which FilterBody's kind switch does not recognize as a
// discovery document. Both of the new fail-closed checks (the non-JSON
// hardening and FilterBody's unrecognized-kind default) must not fire on a
// non-200 response, or they replace the upstream's real status code with a
// misleading 500.
func TestHandlerPassesThroughNonOKDiscoveryResponses(t *testing.T) {
	t.Run("non-JSON error status is forwarded, not fail-closed", func(t *testing.T) {
		up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too many requests, please try again later."))
		})
		h := harness(t, policy.ModeRONoSecret, up)

		rec := do(t, h, "GET", "/api", true)
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want %d (the upstream's real status must survive)", rec.Code, http.StatusTooManyRequests)
		}
	})

	t.Run("JSON Status error body is forwarded, not fail-closed", func(t *testing.T) {
		up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"ServiceUnavailable","code":503}`))
		})
		h := harness(t, policy.ModeRONoSecret, up)

		rec := do(t, h, "GET", "/apis", true)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d (a Status error body must not trip FilterBody's unrecognized-kind default)", rec.Code, http.StatusServiceUnavailable)
		}
	})
}

// TestHandlerStripsAcceptEncodingBeforeForwarding guards a regression found
// live: `kubectl get pod -A` failed with a 500 ("kubegate could not process
// the cluster response") while a smaller single-namespace list worked fine.
//
// kubectl's Go HTTP client sets its own Accept-Encoding header on every
// outbound request. net/http's Transport only takes over compression
// itself -- adding "Accept-Encoding: gzip" and transparently decompressing
// the response -- when the outbound request has no Accept-Encoding header
// at all. Forwarding the guest's header verbatim defeated that: a real
// apiserver compresses responses over a size threshold (which -A's larger
// body crosses and a small list may not), so kubegate received raw gzip
// bytes with Content-Type: application/json, tried to JSON-decode them for
// redaction, and failed closed -- masking a perfectly good response as a
// generic 500.
func TestHandlerStripsAcceptEncodingBeforeForwarding(t *testing.T) {
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	h := harness(t, policy.ModeRONoSecret, up)

	// A distinctive, non-negotiable value: net/http's Transport only ever
	// adds "gzip" itself, so if this reaches the fake upstream verbatim,
	// kubegate forwarded the guest's header instead of stripping it --
	// which would disable the transport's transparent decompression and
	// reproduce the bug.
	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Accept-Encoding", "br")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if up.lastHeader.Get("Accept-Encoding") == "br" {
		t.Error("upstream saw the guest's Accept-Encoding verbatim: kubegate must strip it so net/http's transport manages compression itself")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"kind":"PodList"`) {
		t.Errorf("body = %s, want the decompressed PodList", rec.Body.String())
	}
}

// TestHandlerBuffersResponsesUpToTheResponseCap guards a second regression
// found live, right after the compression fix above: a real, uncompressed
// `kubectl get pods -A` against a real cluster still failed with the same
// "kubegate could not process the cluster response" error, now diagnosed
// (via the host stderr log modifyResponse emits on this path) as "invalid
// character ' ' in string escape code" at exactly 8388608 bytes --
// MaxBodyBytes, the REQUEST-body cap, was being reused by mistake to also
// cap the RESPONSE buffer read in modifyResponse. A real cluster's own list
// response is exactly what a read-only mode's kubectl commands exist to
// return and can legitimately be far larger than any request body ever
// would be; truncating it mid-string produced invalid JSON that redact.Body
// correctly, but misleadingly, rejected.
//
// MaxResponseBodyBytes is now a separate cap, and a response that exceeds
// it fails with an explicit "response exceeds N bytes" diagnosis rather
// than falling through to a confusing JSON decode error. This test lowers
// the cap to a size a unit test can afford to allocate rather than proving
// the fix by allocating a genuine 128 MiB body.
func TestHandlerBuffersResponsesUpToTheResponseCap(t *testing.T) {
	origCap := MaxResponseBodyBytes
	MaxResponseBodyBytes = 1024
	t.Cleanup(func() { MaxResponseBodyBytes = origCap })

	t.Run("under the cap passes through untouched", func(t *testing.T) {
		body := fmt.Sprintf(`{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[],"filler":"%s"}`,
			strings.Repeat("a", 800))
		up := jsonUpstream(t, body)
		h := harness(t, policy.ModeRONoSecret, up)

		rec := do(t, h, "GET", "/api/v1/pods", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != body {
			t.Errorf("body was altered even though nothing needed redacting:\ngot  %s\nwant %s", rec.Body.String(), body)
		}
	})

	t.Run("over the cap fails closed with a diagnosable message, not a truncated-JSON parse error", func(t *testing.T) {
		body := fmt.Sprintf(`{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[],"filler":"%s"}`,
			strings.Repeat("a", 2000))
		up := jsonUpstream(t, body)
		h := harness(t, policy.ModeRONoSecret, up)

		var logbuf bytes.Buffer
		origOut := log.Writer()
		log.SetOutput(&logbuf)
		t.Cleanup(func() { log.SetOutput(origOut) })

		rec := do(t, h, "GET", "/api/v1/pods", true)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		if !strings.Contains(logbuf.String(), "response exceeds") {
			t.Errorf("expected the explicit cap-exceeded diagnosis in the host log, got: %s", logbuf.String())
		}
		if strings.Contains(logbuf.String(), "invalid character") {
			t.Errorf("hit the JSON-decode error path instead of the explicit cap check: %s", logbuf.String())
		}
	})
}

// TestHandlerWatchQueryParamCannotBypassDiscoveryFiltering guards the second
// critical finding: isWatch must key off the parsed policy.Request, not raw
// client-controlled query parameters. Appending ?watch=true to a discovery
// path used to force the response down the streaming path, which applies no
// discovery filtering at all.
func TestHandlerWatchQueryParamCannotBypassDiscoveryFiltering(t *testing.T) {
	up := jsonUpstream(t, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[
		{"name":"pods","namespaced":true,"kind":"Pod","verbs":["list"]},
		{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["list"]}]}`)
	h := harness(t, policy.ModeRONoSecret, up)

	for _, target := range []string{"/api/v1?watch=true", "/api/v1?follow=true"} {
		rec := do(t, h, "GET", target, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body = %s", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "secrets") {
			t.Errorf("%s: discovery must not advertise secrets in strict mode, watch/follow query params must not bypass filtering: %s",
				target, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "pods") {
			t.Errorf("%s: discovery must still advertise pods: %s", target, rec.Body.String())
		}
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
