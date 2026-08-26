package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/anantadwi13/kubegate/internal/audit"
	"github.com/anantadwi13/kubegate/internal/authn"
	"github.com/anantadwi13/kubegate/internal/discovery"
	"github.com/anantadwi13/kubegate/internal/policy"
	"github.com/anantadwi13/kubegate/internal/redact"
	"github.com/anantadwi13/kubegate/internal/reqinfo"
	"github.com/anantadwi13/kubegate/internal/upstream"
)

// MaxBodyBytes caps request bodies in every mode. The read-only modes permit
// no body-bearing verbs, so a body arriving there is already anomalous and
// should be truncated rather than buffered.
const MaxBodyBytes = 8 << 20

// protobufMediaType is what client-go asks for by default. Redacting it
// would require the full scheme, so the strict mode negotiates it away.
const protobufMediaType = "application/vnd.kubernetes.protobuf"

// Options are the collaborators a handler needs. All are required.
type Options struct {
	Upstream *upstream.Upstream
	Engine   *policy.Engine
	Auth     *authn.Authenticator
	Audit    *audit.Logger
}

type handler struct {
	opts   Options
	parser *reqinfo.Parser
	proxy  *httputil.ReverseProxy
}

// NewHandler wires the middleware chain.
func NewHandler(o Options) (http.Handler, error) {
	if o.Upstream == nil || o.Engine == nil || o.Auth == nil || o.Audit == nil {
		return nil, errors.New("server: Upstream, Engine, Auth, and Audit are all required")
	}

	h := &handler{opts: o, parser: reqinfo.New()}
	base := o.Upstream.BaseURL()

	h.proxy = &httputil.ReverseProxy{
		Transport: o.Upstream.Transport(),
		// FlushInterval -1 makes watch and logs --follow stream instead of
		// buffering, which is what stops kubectl get -w looking hung.
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = base.Scheme
			r.Out.URL.Host = base.Host
			r.Out.Host = base.Host
		},
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   writeProxyError,
	}
	return h, nil
}

// errRedaction marks a failure to transform a response body, so the error
// handler can distinguish "we could not inspect the payload" (our fault, 500)
// from "we could not reach the cluster" (502).
type errRedaction struct{ err error }

func (e *errRedaction) Error() string { return "redaction failed: " + e.err.Error() }
func (e *errRedaction) Unwrap() error { return e.err }

// writeProxyError maps a forwarding failure onto the status code the spec
// requires. Each code tells the operator something different, so collapsing
// them all into 502 would throw away the only diagnostic the guest ever sees.
//
// No branch ever passes err.Error() (or anything derived from the raw
// transport/redaction error) into the message: a Go error can carry dial
// addresses, file paths, or other internal detail that must never reach the
// guest. Every message below is a fixed, hand-authored string.
func writeProxyError(w http.ResponseWriter, _ *http.Request, err error) {
	var re *errRedaction
	switch {
	case errors.As(err, &re):
		// Never forward bytes we could not inspect.
		WriteStatus(w, http.StatusInternalServerError, string(metav1.StatusReasonInternalError),
			"kubegate could not process the cluster response and refused to forward it unchecked")

	case errors.Is(err, upstream.ErrCredentialsUnavailable):
		WriteStatus(w, http.StatusServiceUnavailable, "ServiceUnavailable",
			"kubegate cannot authenticate to the cluster; re-run your login on the host")

	case isTimeout(err):
		WriteStatus(w, http.StatusGatewayTimeout, "Timeout",
			"the cluster did not respond in time")

	case errors.Is(err, http.ErrHandlerTimeout):
		WriteStatus(w, http.StatusGatewayTimeout, "Timeout",
			"the cluster did not respond in time")

	default:
		WriteStatus(w, http.StatusBadGateway, string(metav1.StatusReasonInternalError),
			"kubegate could not reach the cluster")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TLSConfig returns the listener's TLS configuration.
//
// HTTP/2 is deliberately not offered. Connection: Upgrade does not exist in
// HTTP/2 -- RFC 8441 tunnels WebSocket through extended CONNECT instead -- so
// the upgrade check would silently stop applying. The subresource denial in
// policy remains authoritative either way, but a defense-in-depth layer that
// quietly lapses is worse than one that is absent.
func TLSConfig(cert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	req, decision, redacted := h.authorize(rec, r)

	h.opts.Audit.Log(audit.Entry{
		Remote:   r.RemoteAddr,
		Method:   r.Method,
		Request:  req,
		Decision: decision,
		Status:   rec.status,
		Bytes:    rec.bytes,
		Duration: time.Since(start),
		Redacted: redacted,
	})
}

// redactedKey is the context key under which authorize stashes a pointer
// that modifyResponse reports into, so ServeHTTP can log what actually
// happened to the body rather than guessing from the mode alone.
type redactedKeyType struct{}

var redactedKey = redactedKeyType{}

// authorize runs the chain and, when everything passes, forwards. It returns
// what it decided so the caller can audit it, along with whether the
// response body was actually changed by redaction or discovery filtering
// (as opposed to merely being eligible for it).
func (h *handler) authorize(w http.ResponseWriter, r *http.Request) (policy.Request, policy.Decision, bool) {
	// Cheap outer guard, before any parsing. The authoritative block on
	// interactive access is the */exec, */attach, */portforward, */proxy
	// subresource denial in policy.
	if isUpgrade(r.Header) {
		d := policy.Decision{Reason: "protocol upgrade requests are never forwarded"}
		WriteStatus(w, http.StatusForbidden, string(metav1.StatusReasonForbidden),
			"denied by kubegate policy: "+d.Reason)
		return policy.Request{Path: r.URL.Path}, d, false
	}

	if err := h.opts.Auth.Authenticate(r); err != nil {
		WriteUnauthorized(w)
		return policy.Request{Path: r.URL.Path}, policy.Decision{Reason: "authentication failed"}, false
	}

	// Erase every header through which a client could assert an identity.
	// Done immediately after authentication so nothing downstream can see
	// them, let alone forward them.
	authn.Scrub(r.Header)

	req, err := h.parser.Parse(r)
	if err != nil {
		d := policy.Decision{Reason: "request path could not be parsed"}
		WriteStatus(w, http.StatusForbidden, string(metav1.StatusReasonForbidden),
			"denied by kubegate policy: "+d.Reason)
		return policy.Request{Path: r.URL.Path}, d, false
	}

	if d := h.opts.Engine.Authorize(req); !d.Allow {
		WriteForbidden(w, req, h.opts.Engine.Mode(), d.Reason)
		return req, d, false
	}

	if h.opts.Engine.RedactionEnabled() {
		if !negotiateJSON(r.Header) {
			d := policy.Decision{Reason: "mode " + string(h.opts.Engine.Mode()) + " serves JSON only"}
			WriteStatus(w, http.StatusNotAcceptable, "NotAcceptable",
				"kubegate cannot redact protobuf responses; request application/json")
			return req, d, false
		}
	}

	// A declared length over the cap is refused up front, so the caller gets
	// a real 413 rather than a torn connection. MaxBytesReader stays as the
	// backstop for a body that lies about its length or is chunked.
	if r.ContentLength > MaxBodyBytes {
		d := policy.Decision{Reason: fmt.Sprintf("request body exceeds %d bytes", MaxBodyBytes)}
		WriteStatus(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge",
			fmt.Sprintf("kubegate limits request bodies to %d bytes", MaxBodyBytes))
		return req, d, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	// A per-request flag that modifyResponse sets only when it actually
	// changed bytes (as reported by redact.Body / discovery.FilterBody),
	// never merely because the mode makes redaction eligible. ServeHTTP
	// reads it back after the proxy round trip completes so the audit log
	// reflects what really happened to this response, not a guess.
	var changed atomic.Bool
	r = r.WithContext(context.WithValue(r.Context(), redactedKey, &changed))

	h.proxy.ServeHTTP(w, r)
	return req, policy.Allowed(), changed.Load()
}

// modifyResponse applies discovery filtering and redaction.
func (h *handler) modifyResponse(resp *http.Response) error {
	if !h.opts.Engine.RedactionEnabled() && !discovery.IsDiscoveryPath(resp.Request.URL.Path) {
		return nil
	}
	if !isJSON(resp.Header.Get("Content-Type")) {
		return nil
	}

	// A watch stream is transformed frame by frame as it arrives; buffering
	// it would defeat the point of watching. redact.Stream reports only an
	// error, not whether any frame actually changed, so the audit flag is
	// not set here: a watch response's Redacted stays false rather than
	// claiming a certainty we do not have.
	if isWatch(resp) {
		if !h.opts.Engine.RedactionEnabled() {
			return nil
		}
		src := resp.Body
		pr, pw := io.Pipe()
		resp.Body = pr
		go func() {
			err := redact.Stream(pw, src, nil)
			_ = src.Close()
			_ = pw.CloseWithError(err)
		}()
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	closeErr := resp.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	out := body
	var changed bool
	if discovery.IsDiscoveryPath(resp.Request.URL.Path) {
		filtered, filterChanged, ferr := discovery.FilterBody(h.opts.Engine, resp.Request.URL.Path, out)
		if ferr != nil {
			return &errRedaction{ferr}
		}
		out = filtered
		changed = changed || filterChanged
	}
	if h.opts.Engine.RedactionEnabled() && resp.StatusCode == http.StatusOK {
		redacted, redactChanged, rerr := redact.Body(out)
		if rerr != nil {
			// Never forward bytes we could not inspect: failing open here
			// would silently void the mode's guarantee.
			return &errRedaction{rerr}
		}
		out = redacted
		changed = changed || redactChanged
	}

	if changed {
		if flag, ok := resp.Request.Context().Value(redactedKey).(*atomic.Bool); ok {
			flag.Store(true)
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
	return nil
}

func isUpgrade(h http.Header) bool {
	for _, v := range h.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return h.Get("Upgrade") != ""
}

func isJSON(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "json")
}

func isWatch(resp *http.Response) bool {
	q := resp.Request.URL.Query()
	if v := q.Get("watch"); v != "" && v != "false" && v != "0" {
		return true
	}
	if v := q.Get("follow"); v != "" && v != "false" && v != "0" {
		return true
	}
	return strings.Contains(resp.Request.URL.Path, "/watch/")
}

// negotiateJSON removes protobuf from Accept, reporting whether a
// JSON-family response is still possible. An Accept of protobuf only leaves
// nothing we can redact.
func negotiateJSON(h http.Header) bool {
	raw := h.Get("Accept")
	if raw == "" {
		h.Set("Accept", "application/json")
		return true
	}
	var kept []string
	for _, part := range strings.Split(raw, ",") {
		if strings.Contains(strings.ToLower(part), protobufMediaType) {
			continue
		}
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	if len(kept) == 0 {
		return false
	}
	h.Set("Accept", strings.Join(kept, ", "))
	return true
}

// statusRecorder captures what was actually sent, for the audit line.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Flush forwards flushes so streaming responses are not held up by the
// wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
