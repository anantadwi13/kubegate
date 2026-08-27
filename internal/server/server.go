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

			// Strip the client's own Accept-Encoding. net/http's Transport
			// only takes over compression itself -- adding its own
			// "Accept-Encoding: gzip" and transparently decompressing the
			// response before handoff -- when the outbound request carries
			// no Accept-Encoding header at all. Forwarding the guest's
			// header verbatim (kubectl's Go HTTP client sets one on every
			// request) defeats that: a real apiserver compresses large
			// bodies (kubectl get pods -A easily crosses the size
			// threshold; a small single-namespace list may not), and
			// modifyResponse then tries to JSON-decode raw gzip bytes,
			// fails, and fails closed with a 500 that has nothing to do
			// with the actual response. Dropping the header restores the
			// transport's own transparent handling, so resp.Body is
			// always already the decompressed bytes modifyResponse
			// expects.
			r.Out.Header.Del("Accept-Encoding")
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

// reqKey is the context key under which authorize stashes the already-
// parsed policy.Request, so modifyResponse can route by policy-relevant
// fields (verb, resource, subresource) instead of raw, client-controlled
// query parameters on the outbound URL. Keying streaming-vs-buffered
// routing off ?watch=/?follow= directly let a client force ANY response
// (e.g. a discovery document) down the unfiltered streaming path just by
// appending the query parameter to an unrelated URL.
type reqKeyType struct{}

var reqKey = reqKeyType{}

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
	ctx := context.WithValue(r.Context(), redactedKey, &changed)
	ctx = context.WithValue(ctx, reqKey, req)
	r = r.WithContext(ctx)

	h.proxy.ServeHTTP(w, r)
	return req, policy.Allowed(), changed.Load()
}

// modifyResponse applies discovery filtering and redaction.
func (h *handler) modifyResponse(resp *http.Response) error {
	isDiscovery := discovery.IsDiscoveryPath(resp.Request.URL.Path)
	if !h.opts.Engine.RedactionEnabled() && !isDiscovery {
		return nil
	}

	req, _ := resp.Request.Context().Value(reqKey).(policy.Request)

	if !isJSON(resp.Header.Get("Content-Type")) {
		// Only fail closed for responses this pipeline actually promises to
		// transform: a successful discovery document, or a genuine
		// resource response (objects/Lists/Tables, which is what
		// redact.Body acts on) -- and only on 200, mirroring the
		// redact.Body gate below. A non-200 response is an upstream error
		// (rate limiting under API Priority and Fairness, a timeout, ...)
		// and is not guaranteed to be JSON even at a discovery or resource
		// path -- APF has been observed answering a rejected discovery
		// request with a text/plain body. Treating that as "unexpected"
		// would replace the upstream's real status (e.g. 429) with a
		// misleading 500 fail-closed error.
		//
		// Non-resource, non-discovery endpoints -- /openapi/v2,
		// /openapi/v3/*, /version -- are never filtered in any mode (see
		// README "What it does not provide") and are not guaranteed to be
		// JSON even when JSON was requested; a real apiserver's
		// /openapi/v3 root index answers text/plain regardless of Accept.
		// pods/log is the same story for a resource response: the kubelet
		// ignores content negotiation for it and always streams plain
		// text, in every mode.
		expectsJSON := resp.StatusCode == http.StatusOK &&
			(isDiscovery || (req.IsResourceRequest && !isPodLog(req)))
		if h.opts.Engine.RedactionEnabled() && expectsJSON {
			// negotiateJSON forced a JSON-family Accept for this request
			// precisely so the response would always be something we can
			// inspect. Getting anything else back means either the
			// upstream ignored that or the safeguard has a gap; either
			// way, forwarding it unfiltered would silently void the
			// mode's guarantee, so fail closed instead of passing it
			// through (defense in depth alongside the Accept rewrite).
			return &errRedaction{fmt.Errorf(
				"expected a JSON-family response for %s, got Content-Type %q",
				resp.Request.URL.Path, resp.Header.Get("Content-Type"))}
		}
		return nil
	}

	// A watch stream is transformed frame by frame as it arrives; buffering
	// it would defeat the point of watching. redact.Stream reports only an
	// error, not whether any frame actually changed, so the audit flag is
	// not set here: a watch response's Redacted stays false rather than
	// claiming a certainty we do not have.
	//
	// A discovery document is never watched in real Kubernetes, and its
	// filtering must always run through the buffered path below: routing
	// it into the streaming branch on a client-controlled ?watch=/?follow=
	// query parameter would skip discovery filtering entirely, since
	// redact.Stream only ever redacts a frame's "object" field.
	if !isDiscovery && isWatch(req, resp.Request) {
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
	// Only a successful discovery document is something FilterBody's kind
	// switch understands. A non-200 response at a discovery path is an
	// upstream error -- kind "Status", not one of the discovery kinds --
	// and must pass through with its real status code rather than
	// tripping FilterBody's fail-closed "unrecognized kind" default.
	if isDiscovery && resp.StatusCode == http.StatusOK {
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

// isPodLog reports whether req targets the pods/log subresource, the one
// subresource unconditionally readable in every mode (design spec §2) and
// exempt from the JSON-family expectations the rest of this file enforces:
// the kubelet ignores content negotiation for it and always streams plain
// text.
func isPodLog(req policy.Request) bool {
	return req.Resource == "pods" && req.Subresource == "log"
}

// isWatch reports whether resp should be streamed frame-by-frame rather
// than buffered, keyed off the already-PARSED policy.Request rather than
// raw, client-controlled query parameters on the request URL. Deciding this
// from ?watch=/?follow= directly let a client force any response -- a
// discovery document included -- down the streaming path, which applies no
// discovery filtering at all.
//
// Per the design spec, this is: the parsed verb is "watch", or the request
// targets pods/log with follow=true. "follow" is a kubelet-specific query
// parameter RequestInfoFactory does not parse into the verb, so it is read
// directly here, but only once req has already established (from the
// authoritative parser) that this really is a pods/log request.
func isWatch(req policy.Request, r *http.Request) bool {
	if req.Verb == "watch" {
		return true
	}
	if isPodLog(req) {
		if v := r.URL.Query().Get("follow"); v != "" && v != "false" && v != "0" {
			return true
		}
	}
	return false
}

// negotiateJSON rewrites the outbound Accept header to an ALLOWLIST of
// JSON-family media types, reporting whether a JSON-family response is
// still possible.
//
// This used to be a denylist that stripped only protobuf and forwarded
// everything else -- including "application/yaml" -- unchanged. Since
// modifyResponse only redacts and discovery-filters JSON bodies (isJSON),
// that let a client route any response around the entire filtering
// pipeline just by asking for a media type nobody thought to denylist.
// Allowlisting is the only version of this that cannot be bypassed that
// way.
//
// A structured JSON media type survives intact, params and all -- e.g.
// "application/json;as=Table;g=meta.k8s.io;v=v1", which is exactly what
// kubectl sends for `-o wide`-shaped output (see design spec §7.3). A bare
// wildcard ("*/*" or "application/*") is rewritten to a concrete
// "application/json" rather than kept as-is, so the upstream is never left
// free to choose a format this proxy cannot inspect.
func negotiateJSON(h http.Header) bool {
	raw := h.Get("Accept")
	if raw == "" {
		h.Set("Accept", "application/json")
		return true
	}
	var kept []string
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		base, params, hasParams := strings.Cut(trimmed, ";")
		switch strings.ToLower(strings.TrimSpace(base)) {
		case "application/json":
			kept = append(kept, trimmed)
		case "*/*", "application/*":
			if hasParams {
				kept = append(kept, "application/json;"+params)
			} else {
				kept = append(kept, "application/json")
			}
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
