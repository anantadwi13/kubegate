package authn

import (
	"errors"
	"net/http"
	"testing"
)

func TestNewRejectsEmptyToken(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("an empty token must be rejected; it would authenticate everyone")
	}
	if _, err := New("short"); err == nil {
		t.Error("a token this short must be rejected")
	}
}

func TestAuthenticate(t *testing.T) {
	const token = "kQ7Zt3xL9pR2vN8mB4cJ6yH1wS5dF0gA"
	a, err := New(token)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		header string
		wantOK bool
	}{
		{"correct token", "Bearer " + token, true},
		{"lowercase scheme", "bearer " + token, true},
		{"no header", "", false},
		{"wrong token", "Bearer wrongwrongwrongwrongwrongwr", false},
		{"right prefix wrong suffix", "Bearer " + token[:len(token)-1] + "X", false},
		{"missing scheme", token, false},
		{"wrong scheme", "Basic " + token, false},
		{"empty bearer", "Bearer ", false},
		{"token with trailing space", "Bearer " + token + " ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/api/v1/pods", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			err := a.Authenticate(r)
			if tc.wantOK && err != nil {
				t.Errorf("Authenticate failed: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Error("Authenticate must fail")
				} else if !errors.Is(err, ErrUnauthenticated) {
					t.Errorf("error %v must wrap ErrUnauthenticated", err)
				}
			}
		})
	}
}

// Scrub is what stops a client smuggling identity through the proxy. Even
// though the host credential is injected downstream, a forwarded
// Impersonate-User would be honoured by the apiserver if the host identity
// is permitted to impersonate.
func TestScrubRemovesIdentityHeaders(t *testing.T) {
	h := http.Header{}
	must := []string{
		"Authorization",
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"Impersonate-Extra-Scopes",
		"Impersonate-Extra-Anything-At-All",
		"X-Remote-User",
		"X-Remote-Group",
		"X-Remote-Extra-Scopes",
	}
	for _, k := range must {
		h.Set(k, "attacker")
	}
	// Headers that must survive: the proxy is still an HTTP proxy.
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "kubectl/v1.31.0")

	Scrub(h)

	for _, k := range must {
		if v := h.Get(k); v != "" {
			t.Errorf("header %q survived scrubbing with value %q", k, v)
		}
	}
	if h.Get("Accept") != "application/json" {
		t.Error("Accept must survive")
	}
	if h.Get("User-Agent") == "" {
		t.Error("User-Agent must survive")
	}
}

func TestScrubIsCaseInsensitive(t *testing.T) {
	// http.Header canonicalizes on Set, so exercise the raw map too.
	h := http.Header{
		"impersonate-user":        []string{"attacker"},
		"IMPERSONATE-GROUP":       []string{"attacker"},
		"x-remote-extra-whatever": []string{"attacker"},
	}
	Scrub(h)
	if len(h) != 0 {
		t.Errorf("non-canonical identity headers survived: %v", h)
	}
}
