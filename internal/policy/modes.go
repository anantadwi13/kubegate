package policy

import "fmt"

// ParseMode converts a --mode flag value into a Mode.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeRONoSecret:
		return ModeRONoSecret, nil
	case ModeROSecret:
		return ModeROSecret, nil
	case ModeRW:
		return ModeRW, nil
	}
	return "", fmt.Errorf("unknown mode %q: want one of %s, %s, %s", s, ModeRONoSecret, ModeROSecret, ModeRW)
}

// knownVerbs is every Kubernetes verb kubegate is willing to forward.
// "proxy" is deliberately absent: it is the legacy verb-via-path form and is
// denied outright. So is "", which is what unrecognized HTTP methods produce.
var knownVerbs = map[string]bool{
	"get": true, "list": true, "watch": true,
	"create": true, "update": true, "patch": true,
	"delete": true, "deletecollection": true,
}

var readVerbs = map[string]bool{"get": true, "list": true, "watch": true}

// universalDenyRules are refused in every mode and cannot be granted by a
// --policy extension file.
var universalDenyRules = RuleSet{
	// Interactive session and proxy subresources, across every resource and
	// group. Because these can never be forwarded, kubegate implements no
	// SPDY or WebSocket upgrade handling at all.
	{
		APIGroups: []string{"*"},
		Resources: []string{"*/exec", "*/attach", "*/portforward", "*/proxy"},
		Verbs:     []string{"*"},
	},
	// TokenRequest mints a real cluster credential the caller could carry
	// straight to the apiserver, escaping kubegate entirely.
	{
		APIGroups: []string{""},
		Resources: []string{"serviceaccounts/token"},
		Verbs:     []string{"*"},
	},
	// CSR writes mint a client certificate the same way. Reads stay
	// permitted: a CSR holds the request and any issued certificate, never
	// the private key.
	{
		APIGroups: []string{"certificates.k8s.io"},
		Resources: []string{"certificatesigningrequests"},
		Verbs:     []string{"create", "update", "patch", "delete", "deletecollection"},
	},
	{
		APIGroups: []string{"certificates.k8s.io"},
		Resources: []string{"certificatesigningrequests/approval", "certificatesigningrequests/status"},
		Verbs:     []string{"*"},
	},
}

// universalDenyDecision applies the checks that hold in every mode.
func universalDenyDecision(req Request) Decision {
	// Verb "proxy" is NOT the same check as the */proxy subresource rule
	// below. RequestInfoFactory treats proxy as a special verb expressible
	// as a path prefix, so GET /api/v1/proxy/namespaces/x/pods/y/foo parses
	// to {verb: proxy, resource: pods, subresource: ""}. Matching only on
	// subresource would wave the legacy proxy path straight through.
	if req.Verb == "proxy" {
		return Decision{Reason: "legacy verb-via-path proxy requests are never forwarded"}
	}
	// Unrecognized HTTP methods (OPTIONS, TRACE) parse to an empty verb.
	if req.Verb == "" {
		return Decision{Reason: "request has no recognizable Kubernetes verb"}
	}
	// A resource request with an empty Resource field is malformed and
	// indicates the parser could not identify a resource type. This can occur
	// with malformed URLs like //api/v1//secrets. Such requests cannot be
	// forwarded as they do not identify what to operate on.
	if req.IsResourceRequest && req.Resource == "" {
		return Decision{Reason: "request has no recognizable resource type"}
	}
	if universalDenyRules.Matches(req) {
		return Decision{Reason: fmt.Sprintf("%s is never forwarded by kubegate", resourceDesc(req))}
	}
	return Allowed()
}

// verbGateDecision enforces the mode's verb tier before any resource lookup.
func verbGateDecision(m Mode, req Request) Decision {
	if !knownVerbs[req.Verb] {
		return Decision{Reason: fmt.Sprintf("verb %q is not forwarded", req.Verb)}
	}
	if m == ModeRW {
		return Allowed()
	}
	if !readVerbs[req.Verb] {
		return Decision{Reason: fmt.Sprintf("verb %q requires mode %s", req.Verb, ModeRW)}
	}
	return Allowed()
}

// roNoSecretAllow is the curated allowlist for the strict mode.
//
// The organizing principle is workload observability, not security posture.
// RBAC bindings, CSRs, and admission webhooks describe how the cluster is
// secured; they are rarely needed to find out why a Deployment is
// crashlooping, and they map the environment for an attacker. They stay out
// even though none of them holds a secret.
var roNoSecretAllow = RuleSet{
	{
		APIGroups: []string{""},
		Resources: []string{
			"pods", "pods/status", "pods/log",
			"services", "endpoints", "configmaps", "namespaces",
			"nodes", "nodes/status", "events",
			"persistentvolumes", "persistentvolumeclaims",
			"replicationcontrollers", "serviceaccounts",
			"limitranges", "resourcequotas",
		},
		Verbs: []string{"get", "list", "watch"},
	},
	{
		APIGroups: []string{"apps"},
		Resources: []string{
			"deployments", "deployments/status", "replicasets",
			"statefulsets", "daemonsets", "controllerrevisions",
		},
		Verbs: []string{"get", "list", "watch"},
	},
	{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "ingressclasses", "networkpolicies"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list", "watch"}},
	// Kubernetes has two events groups: kubectl describe reads the core one,
	// kubectl events reads this one. Omitting either loses describe's event
	// footer, which is most of its diagnostic value.
	{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"autoscaling"}, Resources: []string{"horizontalpodautoscalers"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"policy"}, Resources: []string{"poddisruptionbudgets"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"storage.k8s.io"}, Resources: []string{"storageclasses", "csidrivers", "csinodes", "volumeattachments"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"scheduling.k8s.io"}, Resources: []string{"priorityclasses"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"node.k8s.io"}, Resources: []string{"runtimeclasses"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "list", "watch"}},
	{APIGroups: []string{"metrics.k8s.io"}, Resources: []string{"pods", "nodes"}, Verbs: []string{"get", "list", "watch"}},
	// The CRD schemas, never the instances.
	{APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"}, Verbs: []string{"get", "list", "watch"}},
}

// modeResourceDecision applies the mode's resource policy. extra holds the
// --policy extension rules and is meaningful only in ro-nosecret.
//
// ro-nosecret is an allowlist and fails closed, because it is the only mode
// that promises anything about content: the set of resources holding secret
// material is open-ended (ExternalSecret, SealedSecret, VaultStaticSecret,
// and whatever an operator installs next week), so a denylist could not keep
// that promise. The other two modes already concede secret access, so a
// denylist there costs nothing and avoids blocking work on every new CRD.
func modeResourceDecision(m Mode, extra RuleSet, req Request) Decision {
	if m != ModeRONoSecret {
		return Allowed()
	}
	if roNoSecretAllow.Matches(req) || extra.Matches(req) {
		return Allowed()
	}
	return Decision{Reason: fmt.Sprintf("%s is not in the %s allowlist", resourceDesc(req), ModeRONoSecret)}
}

// resourceDesc renders a request the way a Kubernetes error message would.
func resourceDesc(req Request) string {
	name := req.Resource
	if req.Subresource != "" {
		name += "/" + req.Subresource
	}
	if req.APIGroup != "" {
		name += "." + req.APIGroup
	}
	return name
}
