package policy

import (
	"fmt"
	"strings"
)

// nonResourceAllowExact is the complete set of fixed non-resource paths any
// mode permits. kubectl cannot function without discovery and OpenAPI, and
// it needs nothing else.
var nonResourceAllowExact = map[string]bool{
	"/version":    true,
	"/api":        true,
	"/api/v1":     true,
	"/apis":       true,
	"/openapi/v2": true,
	"/openapi/v3": true,
}

// nonResourceDecision authorizes a non-resource request by exact match.
//
// This is an allowlist and must stay one -- but not because of
// "//api/v1//secrets". That path was measured against the real
// RequestInfoFactory (v0.36.4) and does NOT fail the APIPrefixes check or
// arrive here: splitPath's doubled slash produces an empty path segment
// that becomes an empty Resource field, so it parses to a RESOURCE request
// (IsResourceRequest = true, Resource = ""). It is denied by
// universalDenyDecision's explicit Resource == "" check (modes.go), never
// reaching the non-resource policy at all. Loosening this function into
// prefix or cleaned-path matching is still exactly the kind of change that
// invites an authorization bypass -- it just isn't this particular path.
func nonResourceDecision(path string) Decision {
	if nonResourceAllowExact[path] {
		return Allowed()
	}

	// Per-group and per-group-version discovery: /apis/<group> and
	// /apis/<group>/<version>. Nothing deeper, and no empty segments.
	if rest, ok := strings.CutPrefix(path, "/apis/"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) <= 2 {
			ok := true
			for _, p := range parts {
				if p == "" {
					ok = false
					break
				}
			}
			if ok {
				return Allowed()
			}
		}
	}

	// OpenAPI v3 serves a document per group-version under this prefix.
	if strings.HasPrefix(path, "/openapi/v3/") && !strings.Contains(path, "//") {
		return Allowed()
	}

	return Decision{Reason: fmt.Sprintf("non-resource path %q is not permitted", path)}
}
