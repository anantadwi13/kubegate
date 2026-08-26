package policy

import "strings"

// Rule is an RBAC-shaped permission rule. The yaml tags match Kubernetes
// RBAC PolicyRule so that --policy files look like something an operator
// already knows how to read.
type Rule struct {
	APIGroups []string `json:"apiGroups" yaml:"apiGroups"`
	Resources []string `json:"resources" yaml:"resources"`
	Verbs     []string `json:"verbs"     yaml:"verbs"`
}

// RuleSet is an unordered collection of rules. It is evaluated as either an
// allowlist or a denylist by the caller; the set itself only answers "does
// anything here match".
type RuleSet []Rule

// Matches reports whether this rule covers req.
func (r Rule) Matches(req Request) bool {
	return matchAny(r.APIGroups, req.APIGroup) &&
		matchAny(r.Verbs, req.Verb) &&
		r.matchesResource(req.Resource, req.Subresource)
}

// Matches reports whether any rule in the set covers req.
func (rs RuleSet) Matches(req Request) bool {
	for _, r := range rs {
		if r.Matches(req) {
			return true
		}
	}
	return false
}

// matchAny reports whether want appears in list, honouring "*". An empty
// want matches only if "" is explicitly in the list, which prevents empty
// Verb values from matching while allowing "" (core API group) to match.
func matchAny(list []string, want string) bool {
	for _, got := range list {
		if got == "*" {
			return true
		}
		if got == want {
			return true
		}
	}
	return false
}

// matchesResource implements Kubernetes RBAC resource semantics:
//
//   - "*"              matches any resource AND any subresource
//   - "pods"           matches resource pods with NO subresource
//   - "pods/log"       matches resource pods, subresource log
//   - "*/exec"         matches any resource, subresource exec
//
// The second case is the load-bearing one: a rule naming a bare resource
// never grants that resource's subresources, so pods/exec cannot ride in on
// a rule for pods.
func (r Rule) matchesResource(resource, subresource string) bool {
	for _, entry := range r.Resources {
		if entry == "*" {
			return true
		}
		res, sub, hasSub := strings.Cut(entry, "/")
		if !matchOne(res, resource) {
			continue
		}
		if !hasSub {
			if subresource == "" {
				return true
			}
			continue
		}
		if sub == "*" || sub == subresource {
			return true
		}
	}
	return false
}

func matchOne(pattern, want string) bool {
	return pattern == "*" || (pattern == want && want != "")
}
