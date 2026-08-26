// Package audit writes one structured line per request.
//
// The log records what was asked and what was decided, never what was sent
// or returned: bodies and tokens stay out, so the audit trail can never
// become a disclosure channel of its own.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// Entry is one request's audit record.
type Entry struct {
	Remote   string
	Method   string
	Request  policy.Request
	Decision policy.Decision
	Status   int
	Bytes    int64
	Duration time.Duration
	Redacted bool
}

// Logger serializes entries to a writer.
type Logger struct {
	mu      sync.Mutex
	enc     *json.Encoder
	mode    policy.Mode
	context string
}

// NewLogger returns a Logger writing newline-delimited JSON to w.
func NewLogger(w io.Writer, mode policy.Mode, contextName string) *Logger {
	return &Logger{enc: json.NewEncoder(w), mode: mode, context: contextName}
}

// line is the wire shape. Field names are short and stable so the log is
// greppable and jq-able.
type line struct {
	TS          string `json:"ts"`
	Remote      string `json:"remote"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Verb        string `json:"verb"`
	Group       string `json:"group"`
	Version     string `json:"version"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	Mode        string `json:"mode"`
	Context     string `json:"context"`
	Status      int    `json:"status"`
	Bytes       int64  `json:"bytes"`
	DurationMS  int64  `json:"duration_ms"`
	Redacted    bool   `json:"redacted"`
}

// Log writes one entry. Safe for concurrent use: the encoder is guarded so
// concurrent requests cannot produce torn lines.
func (l *Logger) Log(e Entry) {
	decision := "deny"
	if e.Decision.Allow {
		decision = "allow"
	}
	rec := line{
		TS:          time.Now().UTC().Format(time.RFC3339Nano),
		Remote:      e.Remote,
		Method:      e.Method,
		Path:        e.Request.Path,
		Verb:        e.Request.Verb,
		Group:       e.Request.APIGroup,
		Version:     e.Request.APIVersion,
		Resource:    e.Request.Resource,
		Subresource: e.Request.Subresource,
		Namespace:   e.Request.Namespace,
		Name:        e.Request.Name,
		Decision:    decision,
		Reason:      e.Decision.Reason,
		Mode:        string(l.mode),
		Context:     l.context,
		Status:      e.Status,
		Bytes:       e.Bytes,
		DurationMS:  e.Duration.Milliseconds(),
		Redacted:    e.Redacted,
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(rec)
}
