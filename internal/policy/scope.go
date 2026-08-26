package policy

import (
	"fmt"
	"strings"
)

// ResourceScoper answers whether a resource is namespaced. The answer comes
// from the cluster's own discovery document (see internal/discovery), but
// policy takes it as an interface so this package stays pure and the whole
// decision surface remains testable as data.
//
// known reports whether the resource was found at all. An unknown resource
// is denied when namespace scoping is active: failing closed is the whole
// point of the untrusted-VM threat model.
type ResourceScoper interface {
	IsNamespaced(group, version, resource string) (namespaced, known bool)
}

// StaticScoper is a fixed map from "group/version/resource" to whether the
// resource is namespaced. It backs the tests, and internal/discovery builds
// one from a live discovery document.
type StaticScoper map[string]bool

// ScoperKey builds the map key StaticScoper uses. The core group is the
// empty string, so core v1 pods key as "/v1/pods".
func ScoperKey(group, version, resource string) string {
	return strings.Join([]string{group, version, resource}, "/")
}

// IsNamespaced implements ResourceScoper.
func (s StaticScoper) IsNamespaced(group, version, resource string) (bool, bool) {
	ns, ok := s[ScoperKey(group, version, resource)]
	return ns, ok
}

// namespaceDecision applies the optional --namespace allowlist.
//
// When allowed is empty, scoping is off and nothing is constrained; the
// scoper is not consulted at all, which is why the default path needs no
// discovery call.
func namespaceDecision(allowed []string, scoper ResourceScoper, req Request) Decision {
	if len(allowed) == 0 {
		return Allowed()
	}

	if req.Namespace != "" {
		for _, ns := range allowed {
			if ns == req.Namespace {
				return Allowed()
			}
		}
		return Decision{Reason: fmt.Sprintf(
			"namespace %q is outside this proxy's scope (%s)", req.Namespace, strings.Join(allowed, ", "))}
	}

	// An empty namespace is ambiguous: either a cluster-scoped resource,
	// which scoping does not restrict, or a cluster-wide collection of a
	// namespaced resource, which it must deny. Only discovery can tell us
	// which, so an unavailable or silent scoper means deny.
	if scoper == nil {
		return Decision{Reason: fmt.Sprintf(
			"cannot determine whether %s is namespaced; refusing while --namespace is set", resourceDesc(req))}
	}
	namespaced, known := scoper.IsNamespaced(req.APIGroup, req.APIVersion, req.Resource)
	if !known {
		return Decision{Reason: fmt.Sprintf(
			"%s is not present in cluster discovery; refusing while --namespace is set", resourceDesc(req))}
	}
	if !namespaced {
		return Allowed()
	}
	return Decision{Reason: fmt.Sprintf(
		"cluster-wide %s requests are not permitted; name one of %s", resourceDesc(req), strings.Join(allowed, ", "))}
}
