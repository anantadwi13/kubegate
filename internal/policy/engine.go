package policy

import "fmt"

// Config fully describes a proxy's authorization posture. Mode and
// Namespaces come from immutable startup flags, so an Engine's behaviour is
// fixed for the process lifetime.
type Config struct {
	// Mode is the capability tier. Required.
	Mode Mode
	// Namespaces, when non-empty, restricts namespaced requests to this
	// list. Empty means unrestricted.
	Namespaces []string
	// Extra holds --policy extension rules. Only meaningful in ro-nosecret;
	// NewEngine rejects it in any other mode.
	Extra RuleSet
	// Scoper answers whether a resource is namespaced. Required only when
	// Namespaces is non-empty.
	Scoper ResourceScoper
}

// Engine authorizes requests against a fixed Config.
type Engine struct {
	cfg Config
}

// NewEngine validates cfg and returns an Engine.
func NewEngine(cfg Config) (*Engine, error) {
	if _, err := ParseMode(string(cfg.Mode)); err != nil {
		return nil, err
	}
	if len(cfg.Extra) > 0 && cfg.Mode != ModeRONoSecret {
		return nil, fmt.Errorf(
			"--policy extends the %s allowlist and has no meaning in mode %s; "+
				"remove the flag or switch modes", ModeRONoSecret, cfg.Mode)
	}
	return &Engine{cfg: cfg}, nil
}

// Mode returns the engine's immutable mode.
func (e *Engine) Mode() Mode { return e.cfg.Mode }

// RedactionEnabled reports whether responses must be transformed. Only the
// strict mode makes a promise about content, so only it redacts.
func (e *Engine) RedactionEnabled() bool { return e.cfg.Mode == ModeRONoSecret }

// Authorize decides whether req may be forwarded.
//
// Every stage can only deny; none can re-permit something an earlier stage
// rejected. Stages are ordered cheapest-first.
func (e *Engine) Authorize(req Request) Decision {
	if !req.IsResourceRequest {
		return nonResourceDecision(req.Path)
	}
	if d := universalDenyDecision(req); !d.Allow {
		return d
	}
	if d := verbGateDecision(e.cfg.Mode, req); !d.Allow {
		return d
	}
	if d := modeResourceDecision(e.cfg.Mode, e.cfg.Extra, req); !d.Allow {
		return d
	}
	return namespaceDecision(e.cfg.Namespaces, e.cfg.Scoper, req)
}

// PermitsGroup reports whether any rule in this mode's allowlist mentions
// the given API group. It exists for discovery filtering: a group retaining
// no permitted resource is dropped from APIGroupList so that
// kubectl api-resources shows only what works.
//
// The denylist modes permit every group, so they always return true.
func (e *Engine) PermitsGroup(group string) bool {
	if e.cfg.Mode != ModeRONoSecret {
		return true
	}
	for _, rs := range []RuleSet{roNoSecretAllow, e.cfg.Extra} {
		for _, r := range rs {
			for _, g := range r.APIGroups {
				if g == "*" || g == group {
					return true
				}
			}
		}
	}
	return false
}
