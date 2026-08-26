package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

func TestWriteForbiddenRendersKubernetesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	req := policy.Request{IsResourceRequest: true, Resource: "secrets", Verb: "list", Namespace: "app"}
	WriteForbidden(rec, req, policy.ModeRONoSecret, "secrets is not in the ro-nosecret allowlist")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON so kubectl parses it", ct)
	}

	var st struct {
		Kind    string `json:"kind"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
		Code    int    `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("body is not a Status: %v", err)
	}
	if st.Kind != "Status" {
		t.Errorf("kind = %q, want Status", st.Kind)
	}
	if st.Status != "Failure" {
		t.Errorf("status = %q, want Failure", st.Status)
	}
	if st.Reason != "Forbidden" {
		t.Errorf("reason = %q, want Forbidden", st.Reason)
	}
	if st.Code != 403 {
		t.Errorf("code = %d, want 403", st.Code)
	}
	// kubectl prints "Error from server (Forbidden): <message>", so the
	// message has to stand alone as an explanation.
	if !strings.Contains(st.Message, "secrets") {
		t.Errorf("message must name the resource: %q", st.Message)
	}
	if !strings.Contains(st.Message, "ro-nosecret") {
		t.Errorf("message must name the mode so the fix is obvious: %q", st.Message)
	}
	if !strings.Contains(st.Message, "kubegate") {
		t.Errorf("message must identify the proxy, not look like a cluster RBAC denial: %q", st.Message)
	}
}

// Denial messages must not leak where the proxy is pointed.
func TestWriteForbiddenLeaksNothingAboutUpstream(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteForbidden(rec, policy.Request{Resource: "pods", Verb: "get"}, policy.ModeRW, "denied")
	body := rec.Body.String()
	for _, leak := range []string{"https://", "eks.amazonaws.com", "Bearer", "kubeconfig"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks %q: %s", leak, body)
		}
	}
}

func TestWriteUnauthorized(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteUnauthorized(rec)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	var st struct {
		Kind   string `json:"kind"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Kind != "Status" || st.Reason != "Unauthorized" {
		t.Errorf("got kind=%q reason=%q", st.Kind, st.Reason)
	}
}

func TestWriteStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		code   int
		reason string
	}{
		{http.StatusNotAcceptable, "NotAcceptable"},
		{http.StatusServiceUnavailable, "ServiceUnavailable"},
		{http.StatusBadGateway, "InternalError"},
		{http.StatusRequestEntityTooLarge, "RequestEntityTooLarge"},
		{http.StatusInternalServerError, "InternalError"},
	} {
		rec := httptest.NewRecorder()
		WriteStatus(rec, tc.code, tc.reason, "something went wrong")
		if rec.Code != tc.code {
			t.Errorf("code = %d, want %d", rec.Code, tc.code)
		}
		var st struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Errorf("code %d: body is not a Status: %v", tc.code, err)
		}
		if st.Code != tc.code {
			t.Errorf("Status.code = %d, want %d", st.Code, tc.code)
		}
	}
}
