// Package discovery filters discovery documents to what a mode permits, and
// builds the resource-scope map that namespace scoping needs.
package discovery

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// IsDiscoveryPath reports whether path serves a discovery document whose
// body we may need to filter.
func IsDiscoveryPath(path string) bool {
	if path == "/api" || path == "/api/v1" || path == "/apis" {
		return true
	}
	if rest, ok := strings.CutPrefix(path, "/apis/"); ok {
		return len(strings.Split(rest, "/")) <= 2
	}
	return false
}

// FilterBody rewrites a discovery response so it advertises only what the
// mode will actually serve. kubectl api-resources then shows exactly what
// works, turning a confusing 403 into a clean absence.
//
// Only ro-nosecret filters: the denylist modes serve everything they
// advertise, so rewriting would be pure risk.
func FilterBody(e *policy.Engine, path string, body []byte) ([]byte, bool, error) {
	if e.Mode() != policy.ModeRONoSecret || !IsDiscoveryPath(path) {
		return body, false, nil
	}

	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, false, fmt.Errorf("decoding discovery document at %s: %w", path, err)
	}

	var changed bool
	switch root["kind"] {
	case "APIResourceList":
		changed = filterResourceList(e, root)
	case "APIGroupList":
		changed = filterGroupList(e, root)
	default:
		return body, false, nil
	}

	if !changed {
		return body, false, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false, fmt.Errorf("re-encoding discovery document: %w", err)
	}
	return out, true, nil
}

// filterResourceList keeps only the resources the mode permits a read on.
func filterResourceList(e *policy.Engine, root map[string]any) bool {
	resources, ok := root["resources"].([]any)
	if !ok {
		return false
	}
	group, version := splitGroupVersion(str(root["groupVersion"]))

	kept := make([]any, 0, len(resources))
	for _, raw := range resources {
		r, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, sub, _ := strings.Cut(str(r["name"]), "/")
		req := policy.Request{
			IsResourceRequest: true,
			Verb:              "list",
			APIGroup:          group,
			APIVersion:        version,
			Resource:          name,
			Subresource:       sub,
		}
		// A subresource is never listable; probe it with get instead.
		if sub != "" {
			req.Verb = "get"
			req.Name = "probe"
		}
		if e.Authorize(req).Allow {
			kept = append(kept, raw)
		}
	}
	if len(kept) == len(resources) {
		return false
	}
	root["resources"] = kept
	return true
}

// filterGroupList drops groups that retain no permitted resource. Membership
// is decided by probing the mode's policy rather than by consulting the
// allowlist directly, so the two can never disagree.
func filterGroupList(e *policy.Engine, root map[string]any) bool {
	groups, ok := root["groups"].([]any)
	if !ok {
		return false
	}
	kept := make([]any, 0, len(groups))
	for _, raw := range groups {
		g, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if e.PermitsGroup(str(g["name"])) {
			kept = append(kept, raw)
		}
	}
	if len(kept) == len(groups) {
		return false
	}
	root["groups"] = kept
	return true
}

func splitGroupVersion(gv string) (group, version string) {
	if g, v, ok := strings.Cut(gv, "/"); ok {
		return g, v
	}
	return "", gv
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
