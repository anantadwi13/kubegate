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
	var err error
	switch root["kind"] {
	case "APIResourceList":
		changed, err = filterResourceList(e, root)
	case "APIGroupList":
		changed, err = filterGroupList(e, root)
	default:
		return body, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("filtering discovery document at %s: %w", path, err)
	}

	if !changed {
		return body, false, nil
	}
	out, marshalErr := json.Marshal(root)
	if marshalErr != nil {
		return nil, false, fmt.Errorf("re-encoding discovery document: %w", marshalErr)
	}
	return out, true, nil
}

// filterResourceList keeps only the resources the mode permits a read on.
//
// A "resources" field that isn't the array shape a real APIResourceList
// always has (missing, wrong type, ...) is an error rather than a
// passthrough: FilterBody must never fall back to returning the original,
// unfiltered body just because the shape it was asked to filter turned out
// to be ambiguous.
func filterResourceList(e *policy.Engine, root map[string]any) (bool, error) {
	raw, present := root["resources"]
	if !present {
		return false, fmt.Errorf(`APIResourceList has no "resources" field`)
	}
	resources, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf(`APIResourceList "resources" field is not an array`)
	}
	group, version := splitGroupVersion(str(root["groupVersion"]))

	kept := make([]any, 0, len(resources))
	for _, entry := range resources {
		r, ok := entry.(map[string]any)
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
		// AuthorizesResourceKind, not Authorize: this probes whether the
		// resource TYPE exists for the mode, which is independent of which
		// namespace's instances --namespace scoping would let through. Using
		// Authorize here would hit its empty-namespace-is-ambiguous fallback
		// and hide every namespaced resource whenever scoping is active.
		if e.AuthorizesResourceKind(req).Allow {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(resources) {
		return false, nil
	}
	root["resources"] = kept
	return true, nil
}

// filterGroupList drops groups that retain no permitted resource. Membership
// is decided by probing the mode's policy rather than by consulting the
// allowlist directly, so the two can never disagree.
//
// As with filterResourceList, a "groups" field that isn't an array is an
// error, not a passthrough.
func filterGroupList(e *policy.Engine, root map[string]any) (bool, error) {
	raw, present := root["groups"]
	if !present {
		return false, fmt.Errorf(`APIGroupList has no "groups" field`)
	}
	groups, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf(`APIGroupList "groups" field is not an array`)
	}
	kept := make([]any, 0, len(groups))
	for _, entry := range groups {
		g, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if e.PermitsGroup(str(g["name"])) {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(groups) {
		return false, nil
	}
	root["groups"] = kept
	return true, nil
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
