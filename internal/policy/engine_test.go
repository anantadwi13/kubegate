package policy

import (
	"fmt"
	"testing"
)

func mustEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestNewEngineRejectsBadConfig(t *testing.T) {
	if _, err := NewEngine(Config{Mode: "bogus"}); err == nil {
		t.Error("NewEngine must reject an unknown mode")
	}
	// Extension rules only mean something for the allowlist mode; silently
	// ignoring them would let someone believe they had constrained a proxy
	// that is in fact wide open.
	extra := RuleSet{{APIGroups: []string{"example.com"}, Resources: []string{"widgets"}, Verbs: []string{"get"}}}
	for _, m := range []Mode{ModeROSecret, ModeRW} {
		if _, err := NewEngine(Config{Mode: m, Extra: extra}); err == nil {
			t.Errorf("NewEngine must reject extension rules in mode %s", m)
		}
	}
	if _, err := NewEngine(Config{Mode: ModeRONoSecret, Extra: extra}); err != nil {
		t.Errorf("extension rules must be accepted in %s: %v", ModeRONoSecret, err)
	}
}

func TestEngineRedactionEnabled(t *testing.T) {
	if !mustEngine(t, Config{Mode: ModeRONoSecret}).RedactionEnabled() {
		t.Error("ro-nosecret must redact")
	}
	for _, m := range []Mode{ModeROSecret, ModeRW} {
		if mustEngine(t, Config{Mode: m}).RedactionEnabled() {
			t.Errorf("%s must not redact", m)
		}
	}
}

// TestEngineAuthorizeTable is the adversarial table from the spec. Every row
// is a path an attacker or a careless client would actually try.
func TestEngineAuthorizeTable(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		req  Request
		want bool
	}{
		// --- escape hatches, denied in every mode ---
		{"exec", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Subresource: "exec", Namespace: "x", Name: "y", Verb: "create"}, false},
		{"attach", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Subresource: "attach", Namespace: "x", Name: "y", Verb: "create"}, false},
		{"portforward", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Subresource: "portforward", Namespace: "x", Name: "y", Verb: "create"}, false},
		{"pods proxy subresource", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Subresource: "proxy", Namespace: "x", Name: "y", Verb: "get"}, false},
		{"services proxy subresource", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "services", Subresource: "proxy", Namespace: "x", Name: "y", Verb: "get"}, false},
		{"nodes proxy subresource", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "nodes", Subresource: "proxy", Name: "n", Verb: "get"}, false},
		{"legacy verb-via-path proxy", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Verb: "proxy", Namespace: "x", Name: "y"}, false},
		{"serviceaccount token", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "serviceaccounts", Subresource: "token", Namespace: "x", Name: "y", Verb: "create"}, false},
		{"csr approval", ModeRW, Request{IsResourceRequest: true, APIGroup: "certificates.k8s.io", APIVersion: "v1", Resource: "certificatesigningrequests", Subresource: "approval", Name: "c", Verb: "update"}, false},
		{"csr create", ModeRW, Request{IsResourceRequest: true, APIGroup: "certificates.k8s.io", APIVersion: "v1", Resource: "certificatesigningrequests", Verb: "create"}, false},
		{"empty verb", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Verb: ""}, false},

		// --- csr reads stay permitted where the mode allows reads ---
		{"csr list in ro-secret", ModeROSecret, Request{IsResourceRequest: true, APIGroup: "certificates.k8s.io", APIVersion: "v1", Resource: "certificatesigningrequests", Verb: "list"}, true},
		{"csr list in rw", ModeRW, Request{IsResourceRequest: true, APIGroup: "certificates.k8s.io", APIVersion: "v1", Resource: "certificatesigningrequests", Verb: "list"}, true},
		{"csr list denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "certificates.k8s.io", APIVersion: "v1", Resource: "certificatesigningrequests", Verb: "list"}, false},

		// --- secrets ---
		{"secrets denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "secrets", Namespace: "x", Verb: "list"}, false},
		{"legacy watch prefix on secrets", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "secrets", Verb: "watch"}, false},
		{"secrets allowed in ro-secret", ModeROSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "secrets", Namespace: "x", Verb: "list"}, true},
		{"secrets writable in rw", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "secrets", Namespace: "x", Verb: "create"}, true},

		// --- unknown CRDs: fail closed in the strict mode only ---
		{"external-secrets denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "external-secrets.io", APIVersion: "v1beta1", Resource: "externalsecrets", Namespace: "x", Verb: "list"}, false},
		{"sealedsecrets denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "bitnami.com", APIVersion: "v1alpha1", Resource: "sealedsecrets", Namespace: "x", Verb: "list"}, false},
		{"widgets denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "example.com", APIVersion: "v1", Resource: "widgets", Namespace: "x", Verb: "list"}, false},
		{"widgets allowed in ro-secret", ModeROSecret, Request{IsResourceRequest: true, APIGroup: "example.com", APIVersion: "v1", Resource: "widgets", Namespace: "x", Verb: "list"}, true},

		// --- rbac ---
		{"clusterrolebindings denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1", Resource: "clusterrolebindings", Verb: "list"}, false},
		{"clusterrolebindings writable in rw", ModeRW, Request{IsResourceRequest: true, APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1", Resource: "clusterrolebindings", Verb: "create"}, true},

		// --- writes gated by mode ---
		{"delete pod denied in ro-nosecret", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Name: "y", Verb: "delete"}, false},
		{"delete pod denied in ro-secret", ModeROSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Name: "y", Verb: "delete"}, false},
		{"delete pod allowed in rw", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Name: "y", Verb: "delete"}, true},
		{"deletecollection allowed in rw", ModeRW, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Verb: "deletecollection"}, true},

		// --- reads that must keep working in the strict mode ---
		{"pods log", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Subresource: "log", Namespace: "x", Name: "y", Verb: "get"}, true},
		{"core events", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "events", Namespace: "x", Verb: "list"}, true},
		{"events.k8s.io events", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "events.k8s.io", APIVersion: "v1", Resource: "events", Namespace: "x", Verb: "list"}, true},
		{"metrics pods", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "metrics.k8s.io", APIVersion: "v1beta1", Resource: "pods", Namespace: "x", Verb: "list"}, true},
		{"crd schemas", ModeRONoSecret, Request{IsResourceRequest: true, APIGroup: "apiextensions.k8s.io", APIVersion: "v1", Resource: "customresourcedefinitions", Verb: "list"}, true},
		{"watch pods", ModeRONoSecret, Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "x", Verb: "watch"}, true},

		// --- non-resource paths ---
		{"openapi v3", ModeRONoSecret, Request{IsResourceRequest: false, Path: "/openapi/v3", Verb: "get"}, true},
		{"discovery apis", ModeRONoSecret, Request{IsResourceRequest: false, Path: "/apis", Verb: "get"}, true},
		{"metrics endpoint", ModeRW, Request{IsResourceRequest: false, Path: "/metrics", Verb: "get"}, false},
		{"pprof", ModeRW, Request{IsResourceRequest: false, Path: "/debug/pprof/heap", Verb: "get"}, false},
		{"apiserver logs", ModeRW, Request{IsResourceRequest: false, Path: "/logs", Verb: "get"}, false},
		{"double slash arrives as non-resource", ModeRW, Request{IsResourceRequest: false, Path: "//api/v1//secrets", Verb: "get"}, false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.mode, tc.name), func(t *testing.T) {
			e := mustEngine(t, Config{Mode: tc.mode})
			d := e.Authorize(tc.req)
			if d.Allow != tc.want {
				t.Errorf("Authorize = %v, want %v (reason=%q)", d.Allow, tc.want, d.Reason)
			}
			if !d.Allow && d.Reason == "" {
				t.Error("deny must carry a reason")
			}
		})
	}
}

func TestEngineAuthorizeWithNamespaceScope(t *testing.T) {
	cfg := Config{Mode: ModeROSecret, Namespaces: []string{"app"}, Scoper: testScoper()}
	e := mustEngine(t, cfg)

	if d := e.Authorize(Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "app", Verb: "list"}); !d.Allow {
		t.Errorf("in-scope denied: %s", d.Reason)
	}
	if d := e.Authorize(Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "other", Verb: "list"}); d.Allow {
		t.Error("out-of-scope namespace must be denied")
	}
	if d := e.Authorize(Request{IsResourceRequest: true, APIVersion: "v1", Resource: "pods", Namespace: "", Verb: "list"}); d.Allow {
		t.Error("cluster-wide collection must be denied while scoped")
	}
	if d := e.Authorize(Request{IsResourceRequest: true, APIVersion: "v1", Resource: "nodes", Namespace: "", Verb: "list"}); !d.Allow {
		t.Errorf("cluster-scoped resource must stay readable while scoped: %s", d.Reason)
	}
	// Non-resource paths are unaffected by namespace scope.
	if d := e.Authorize(Request{IsResourceRequest: false, Path: "/apis", Verb: "get"}); !d.Allow {
		t.Errorf("discovery denied while scoped: %s", d.Reason)
	}
}

// TestModeMonotonicity asserts the ladder ro-nosecret subset-of ro-secret
// subset-of rw over every group/resource/subresource/verb combination the
// rule sets mention, plus unknown ones.
//
// This catches the class of mistake review misses: a denial added to one
// mode that belonged in the universal denylist, or the reverse. An earlier
// draft of the spec denied certificatesigningrequests outright in rw, which
// made kubectl get csr fail in read-write while succeeding in read-only.
func TestModeMonotonicity(t *testing.T) {
	groups := []string{"", "apps", "batch", "certificates.k8s.io", "rbac.authorization.k8s.io",
		"metrics.k8s.io", "events.k8s.io", "example.com", "external-secrets.io"}
	resources := []string{"pods", "secrets", "configmaps", "deployments", "nodes",
		"serviceaccounts", "certificatesigningrequests", "widgets", "events"}
	subresources := []string{"", "log", "status", "exec", "attach", "portforward", "proxy", "token", "approval", "scale"}
	verbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "proxy", ""}

	engines := map[Mode]*Engine{}
	for _, m := range AllModes {
		engines[m] = mustEngine(t, Config{Mode: m})
	}

	for _, g := range groups {
		for _, r := range resources {
			for _, sub := range subresources {
				for _, v := range verbs {
					req := Request{IsResourceRequest: true, APIGroup: g, APIVersion: "v1", Resource: r, Subresource: sub, Namespace: "x", Verb: v}
					if sub != "" || v == "get" {
						req.Name = "n"
					}
					prev := true
					for i, m := range AllModes {
						got := engines[m].Authorize(req).Allow
						if i > 0 && got == false && prev == true {
							t.Errorf("monotonicity violated at mode %s for %+v: stricter mode allowed but looser denied", m, req)
						}
						prev = got
					}
				}
			}
		}
	}
}
