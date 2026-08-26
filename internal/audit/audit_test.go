package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anantadwi13/kubegate/internal/policy"
)

func TestLogWritesOneJSONLine(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, policy.ModeRONoSecret, "prod-eks")
	l.Log(Entry{
		Remote:   "192.168.5.15:51234",
		Method:   "GET",
		Request:  policy.Request{IsResourceRequest: true, Path: "/api/v1/namespaces/app/secrets", Verb: "list", Resource: "secrets", Namespace: "app"},
		Decision: policy.Decision{Allow: false, Reason: "secrets is not in the ro-nosecret allowlist"},
		Status:   403,
		Bytes:    142,
		Duration: 3 * time.Millisecond,
	})

	out := buf.String()
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Errorf("expected exactly one line, got %q", out)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, k := range []string{"ts", "remote", "method", "path", "verb", "resource",
		"namespace", "decision", "reason", "mode", "context", "status", "bytes", "duration_ms"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing field %q in %v", k, got)
		}
	}
	if got["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", got["decision"])
	}
	if got["mode"] != "ro-nosecret" {
		t.Errorf("mode = %v", got["mode"])
	}
	if got["context"] != "prod-eks" {
		t.Errorf("context = %v", got["context"])
	}
}

func TestLogAllowDecision(t *testing.T) {
	var buf bytes.Buffer
	NewLogger(&buf, policy.ModeRW, "ctx").Log(Entry{
		Method:   "GET",
		Request:  policy.Request{IsResourceRequest: true, Path: "/api/v1/pods", Verb: "list", Resource: "pods"},
		Decision: policy.Decision{Allow: true},
		Status:   200,
	})
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["decision"] != "allow" {
		t.Errorf("decision = %v, want allow", got["decision"])
	}
}

// The audit log must never become a secret-disclosure channel of its own.
func TestLogNeverContainsBodiesOrTokens(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, policy.ModeRW, "ctx")
	l.Log(Entry{
		Remote:   "1.2.3.4:5",
		Method:   "POST",
		Request:  policy.Request{IsResourceRequest: true, Path: "/api/v1/namespaces/app/secrets", Verb: "create", Resource: "secrets"},
		Decision: policy.Decision{Allow: true},
		Status:   201,
	})
	out := buf.String()
	for _, forbidden := range []string{"Bearer", "Authorization", "hunter2", "stringData"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("audit line must not contain %q: %s", forbidden, out)
		}
	}
}

func TestLoggerIsSafeForConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, policy.ModeRW, "ctx")
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				l.Log(Entry{Method: "GET", Request: policy.Request{Path: "/api", Verb: "get"}, Decision: policy.Decision{Allow: true}, Status: 200})
			}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 400 {
		t.Fatalf("got %d lines, want 400; writes are interleaving", len(lines))
	}
	for i, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %d is corrupt, indicating a torn write: %v", i, err)
		}
	}
}
