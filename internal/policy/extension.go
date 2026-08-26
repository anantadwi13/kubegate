package policy

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// extensionFile is the on-disk shape of a --policy file.
type extensionFile struct {
	Rules RuleSet `json:"rules"`
}

// forbiddenExtensionGroups are API groups a --policy file may never name.
// They describe how the cluster is secured rather than how a workload is
// behaving, which is the line the ro-nosecret allowlist draws.
var forbiddenExtensionGroups = map[string]bool{
	"rbac.authorization.k8s.io":    true,
	"certificates.k8s.io":          true,
	"admissionregistration.k8s.io": true,
	"authentication.k8s.io":        true,
	"authorization.k8s.io":         true,
}

// LoadExtension reads and validates a --policy file. A missing or malformed
// file is an error: starting with silently-empty rules would look like a
// working restriction while behaving like a different one.
func LoadExtension(path string) (RuleSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading --policy file: %w", err)
	}
	var f extensionFile
	// UnmarshalStrict rejects unknown fields, so a typo like "deny:" fails
	// loudly instead of being ignored.
	if err := yaml.UnmarshalStrict(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing --policy file %s: %w", path, err)
	}
	if err := ValidateExtension(f.Rules); err != nil {
		return nil, fmt.Errorf("invalid --policy file %s: %w", path, err)
	}
	return f.Rules, nil
}

// ValidateExtension enforces the constraints that keep the extension file
// from undoing the fail-closed guarantee it extends.
func ValidateExtension(rs RuleSet) error {
	if len(rs) == 0 {
		return fmt.Errorf("no rules found; remove the flag instead of passing an empty file")
	}
	for i, r := range rs {
		if len(r.APIGroups) == 0 {
			return fmt.Errorf("rule %d: apiGroups must not be empty", i)
		}
		if len(r.Resources) == 0 {
			return fmt.Errorf("rule %d: resources must not be empty", i)
		}
		if len(r.Verbs) == 0 {
			return fmt.Errorf("rule %d: verbs must not be empty", i)
		}
		for _, g := range r.APIGroups {
			if g == "*" {
				return fmt.Errorf("rule %d: wildcard apiGroups defeat the %s allowlist", i, ModeRONoSecret)
			}
			if forbiddenExtensionGroups[g] {
				return fmt.Errorf("rule %d: apiGroup %q may not be granted through --policy", i, g)
			}
		}
		for _, res := range r.Resources {
			if strings.Contains(res, "*") {
				return fmt.Errorf("rule %d: wildcard resource %q defeats the %s allowlist", i, res, ModeRONoSecret)
			}
			name, _, _ := strings.Cut(res, "/")
			if name == "secrets" {
				return fmt.Errorf("rule %d: secrets may not be granted through --policy; use --mode %s", i, ModeROSecret)
			}
		}
		for _, v := range r.Verbs {
			if !readVerbs[v] {
				return fmt.Errorf("rule %d: verb %q is not permitted; --policy may only grant get, list, watch", i, v)
			}
		}
		// Nothing on the universal denylist may be re-granted. Probe the
		// rule against the denylist rather than string-matching, so the two
		// definitions cannot drift apart.
		for _, res := range r.Resources {
			name, sub, _ := strings.Cut(res, "/")
			for _, g := range r.APIGroups {
				for v := range readVerbs {
					probe := Request{APIGroup: g, Resource: name, Subresource: sub, Verb: v}
					if universalDenyRules.Matches(probe) {
						return fmt.Errorf("rule %d: %s is never forwarded by kubegate and cannot be granted", i, res)
					}
				}
			}
		}
	}
	return nil
}
