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
	case "APIGroupDiscoveryList":
		changed, err = filterAggregatedDiscoveryList(e, root)
	case "APIVersions":
		// The bare /api response: a list of core API versions and server
		// address CIDRs, never a resource listing. There is no resource
		// type here that could be advertised past the mode's allowlist, so
		// this is a deliberate, safe passthrough rather than the
		// fail-closed default below.
		return body, false, nil
	default:
		// An unrecognized kind at a discovery path is never a safe
		// passthrough in ro-nosecret. This exact fail-open shape (an
		// unhandled kind falling through to the original, unfiltered body)
		// is what let APIGroupDiscoveryList leak "secrets" and every
		// denied CRD before it got its own case above -- adding one case
		// at a time and leaving the default permissive just moves the same
		// bug to whichever kind is discovered next. Fail closed instead.
		return nil, false, fmt.Errorf("unrecognized discovery document kind %q at %s", root["kind"], path)
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

// filterAggregatedDiscoveryList is the APIGroupDiscoveryList analog of
// filterResourceList and filterGroupList combined.
//
// kubectl 1.30+ (and any discovery client requesting the
// apidiscovery.k8s.io media type) fetches /api and /apis in one aggregated
// shape instead of walking each group/version's own APIResourceList. Before
// this handled that kind, FilterBody's default case passed it straight
// through unfiltered -- a real fail-open found by driving a current kubectl
// through a real proxy against a real k3s >=1.30 apiserver: strict mode's
// `kubectl api-resources` advertised "secrets" and every denied CRD intact,
// even though direct GETs on them were still correctly denied by Authorize.
// The redaction/policy path must never fail open, so this is fixed the same
// way as the other two shapes: an unexpected field type is an error, never
// a silent passthrough.
func filterAggregatedDiscoveryList(e *policy.Engine, root map[string]any) (bool, error) {
	raw, present := root["items"]
	if !present {
		return false, fmt.Errorf(`APIGroupDiscoveryList has no "items" field`)
	}
	items, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf(`APIGroupDiscoveryList "items" field is not an array`)
	}

	kept := make([]any, 0, len(items))
	var changed bool
	for _, entry := range items {
		g, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		// The core group's entry has no "metadata.name" at all, matching
		// PermitsGroup's and the Request.APIGroup convention that "" means
		// core.
		meta, _ := g["metadata"].(map[string]any)
		group := str(meta["name"])

		if !e.PermitsGroup(group) {
			changed = true
			continue
		}
		vChanged, err := filterAggregatedVersions(e, group, g)
		if err != nil {
			return false, err
		}
		changed = changed || vChanged
		kept = append(kept, g)
	}
	if !changed {
		return false, nil
	}
	root["items"] = kept
	return true, nil
}

func filterAggregatedVersions(e *policy.Engine, group string, g map[string]any) (bool, error) {
	raw, present := g["versions"]
	if !present {
		return false, fmt.Errorf(`APIGroupDiscovery entry for group %q has no "versions" field`, group)
	}
	versions, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf(`APIGroupDiscovery entry for group %q has a non-array "versions" field`, group)
	}
	var changed bool
	for _, entry := range versions {
		v, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		vChanged, err := filterAggregatedResources(e, group, str(v["version"]), v)
		if err != nil {
			return false, err
		}
		changed = changed || vChanged
	}
	return changed, nil
}

func filterAggregatedResources(e *policy.Engine, group, version string, v map[string]any) (bool, error) {
	raw, present := v["resources"]
	if !present {
		// A version can legitimately have no "resources" field at all: a
		// real k3s apiserver was observed advertising metrics.k8s.io/v1beta1
		// with "freshness":"Stale" and no "resources" key whenever the
		// metrics-server backend has registered its APIService but has not
		// answered a discovery call yet. That is the documented meaning of
		// "Stale" -- the aggregator could not gather this group/version's
		// resources right now -- not a malformed response, so there is
		// nothing here to filter. Treating it as an error would turn a
		// transient, entirely normal startup window into a hard failure for
		// every kubectl command, since a client's discovery walk fetches
		// every group up front. A present-but-wrong-typed field is still
		// treated as an error below: that shape is never legitimate.
		return false, nil
	}
	resources, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf(`APIGroupDiscoveryVersion %s/%s has a non-array "resources" field`, group, version)
	}

	kept := make([]any, 0, len(resources))
	var changed bool
	for _, entry := range resources {
		r, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name := str(r["resource"])
		req := policy.Request{
			IsResourceRequest: true,
			Verb:              "list",
			APIGroup:          group,
			APIVersion:        version,
			Resource:          name,
		}
		if !e.AuthorizesResourceKind(req).Allow {
			changed = true
			continue
		}
		if filterAggregatedSubresources(e, group, version, name, r) {
			changed = true
		}
		kept = append(kept, r)
	}
	if changed {
		v["resources"] = kept
	}
	return changed, nil
}

// filterAggregatedSubresources drops entries from a resource's nested
// "subresources" array, mirroring how the flat APIResourceList format
// evaluates a "pods/log"-style entry independently of "pods" itself: a
// subresource is never listable, so it is probed with get/probe exactly as
// filterResourceList does.
func filterAggregatedSubresources(e *policy.Engine, group, version, resource string, r map[string]any) bool {
	raw, present := r["subresources"]
	if !present {
		return false
	}
	subs, ok := raw.([]any)
	if !ok {
		return false
	}

	kept := make([]any, 0, len(subs))
	var changed bool
	for _, entry := range subs {
		s, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		req := policy.Request{
			IsResourceRequest: true,
			Verb:              "get",
			APIGroup:          group,
			APIVersion:        version,
			Resource:          resource,
			Subresource:       str(s["subresource"]),
			Name:              "probe",
		}
		if e.AuthorizesResourceKind(req).Allow {
			kept = append(kept, s)
		} else {
			changed = true
		}
	}
	if changed {
		r["subresources"] = kept
	}
	return changed
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
