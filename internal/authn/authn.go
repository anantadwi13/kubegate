// Package authn authenticates inbound requests against the proxy-scoped
// bearer token, and strips every header a client must not be able to
// influence.
package authn

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnauthenticated signals a missing or incorrect token. Callers map it to
// a 401.
var ErrUnauthenticated = errors.New("unauthenticated")

// minTokenLen guards against a truncated or placeholder token being used by
// accident. The generated token is 32 random bytes base64url-encoded.
const minTokenLen = 32

// Authenticator validates the proxy token.
type Authenticator struct {
	token []byte
}

// New returns an Authenticator for the given token.
func New(token string) (*Authenticator, error) {
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("proxy token must be at least %d characters, got %d", minTokenLen, len(token))
	}
	return &Authenticator{token: []byte(token)}, nil
}

// Authenticate checks the Authorization header.
//
// The comparison is constant-time. A timing-variable compare would let a
// caller on the same network segment recover the token byte by byte, and the
// token is the entire capability.
func (a *Authenticator) Authenticate(r *http.Request) error {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return fmt.Errorf("%w: no Authorization header", ErrUnauthenticated)
	}
	const scheme = "bearer "
	if len(raw) <= len(scheme) || !strings.EqualFold(raw[:len(scheme)], scheme) {
		return fmt.Errorf("%w: Authorization header is not a bearer token", ErrUnauthenticated)
	}
	presented := raw[len(scheme):]
	if subtle.ConstantTimeCompare([]byte(presented), a.token) != 1 {
		return fmt.Errorf("%w: token mismatch", ErrUnauthenticated)
	}
	return nil
}

// scrubExact are headers removed outright.
var scrubExact = map[string]bool{
	"authorization":     true,
	"impersonate-user":  true,
	"impersonate-group": true,
	"impersonate-uid":   true,
}

// scrubPrefixes cover the open-ended header families.
var scrubPrefixes = []string{"impersonate-extra-", "x-remote-"}

// Scrub removes every header through which a client could assert an identity.
//
// A client that sets them is not rejected, only erased: rejecting would leak
// which headers the proxy cares about, and erasing is the stronger property
// anyway. This matters even though the host credential is injected later --
// the apiserver would honour a forwarded Impersonate-User if the host
// identity is permitted to impersonate.
func Scrub(h http.Header) {
	for k := range h {
		lower := strings.ToLower(k)
		if scrubExact[lower] {
			delete(h, k)
			continue
		}
		for _, p := range scrubPrefixes {
			if strings.HasPrefix(lower, p) {
				delete(h, k)
				break
			}
		}
	}
}
