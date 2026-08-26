// Package policy decides whether an inbound Kubernetes API request is
// permitted. It is deliberately pure: it imports neither net/http nor any
// client, so the whole decision surface is testable as data.
package policy

// Request is the policy-relevant view of an inbound request, produced by
// internal/reqinfo from the apiserver's own RequestInfoFactory.
//
// Verb holds a Kubernetes verb (get, list, watch, create, update, patch,
// delete, deletecollection), or "proxy" for the legacy verb-via-path form,
// or "" for an HTTP method the parser does not recognize. Both of those last
// two are denied unconditionally; see modes.go.
type Request struct {
	IsResourceRequest bool
	Path              string // only meaningful when IsResourceRequest is false
	Verb              string
	APIGroup          string // "" is the core group
	APIVersion        string
	Resource          string
	Subresource       string
	Namespace         string // "" means cluster-scoped OR cluster-wide collection
	Name              string
}

// Decision is the result of authorization. Reason is surfaced both in the
// 403 body and in the audit log, so it must be readable by a human holding
// only a kubectl error message.
type Decision struct {
	Allow  bool
	Reason string
}

// Allowed reports a permitted request.
func Allowed() Decision { return Decision{Allow: true} }

// Mode is one of the three capability tiers.
type Mode string

const (
	ModeRONoSecret Mode = "ro-nosecret"
	ModeROSecret   Mode = "ro-secret"
	ModeRW         Mode = "rw"
)

// AllModes is ordered from strictest to loosest. The monotonicity property
// test in engine_test.go relies on this ordering.
var AllModes = []Mode{ModeRONoSecret, ModeROSecret, ModeRW}
