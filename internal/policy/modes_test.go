package policy

import "testing"

func TestParseMode(t *testing.T) {
	for _, s := range []string{"ro-nosecret", "ro-secret", "rw"} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q) returned error: %v", s, err)
		}
	}
	for _, s := range []string{"", "RW", "readonly", "ro", "rw ", "ro_secret"} {
		if _, err := ParseMode(s); err == nil {
			t.Errorf("ParseMode(%q) must fail", s)
		}
	}
}

func TestUniversalDeny(t *testing.T) {
	denied := []struct {
		name string
		req  Request
	}{
		{"pods exec", Request{Resource: "pods", Subresource: "exec", Verb: "create"}},
		{"pods attach", Request{Resource: "pods", Subresource: "attach", Verb: "create"}},
		{"pods portforward", Request{Resource: "pods", Subresource: "portforward", Verb: "create"}},
		{"pods proxy", Request{Resource: "pods", Subresource: "proxy", Verb: "get"}},
		{"services proxy", Request{Resource: "services", Subresource: "proxy", Verb: "get"}},
		{"nodes proxy", Request{Resource: "nodes", Subresource: "proxy", Verb: "get"}},
		{"sa token", Request{Resource: "serviceaccounts", Subresource: "token", Verb: "create"}},
		{"csr create", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create"}},
		{"csr update", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "update"}},
		{"csr patch", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "patch"}},
		{"csr delete", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "delete"}},
		{"csr approval", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Subresource: "approval", Verb: "update"}},
		{"csr status", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Subresource: "status", Verb: "update"}},
		// The bypass the spec records: legacy verb-via-path proxy carries
		// verb=proxy and NO subresource at all.
		{"legacy verb-via-path proxy", Request{Resource: "pods", Verb: "proxy", Namespace: "x", Name: "y"}},
		{"legacy proxy on services", Request{Resource: "services", Verb: "proxy"}},
		// OPTIONS and friends parse to an empty verb.
		{"empty verb", Request{Resource: "pods", Verb: ""}},
		// Malformed resource request with no identifiable resource type.
		{"malformed empty resource", Request{IsResourceRequest: true, Resource: "", Verb: "get"}},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			d := universalDenyDecision(tc.req)
			if d.Allow {
				t.Fatalf("universalDenyDecision allowed %+v", tc.req)
			}
			if d.Reason == "" {
				t.Error("deny must carry a reason")
			}
		})
	}

	allowed := []struct {
		name string
		req  Request
	}{
		{"pods get", Request{Resource: "pods", Verb: "get"}},
		{"pods log", Request{Resource: "pods", Subresource: "log", Verb: "get"}},
		{"pods status", Request{Resource: "pods", Subresource: "status", Verb: "get"}},
		// CSRs stay READABLE; only the minting paths are closed.
		{"csr get", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "get"}},
		{"csr list", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "list"}},
		{"csr watch", Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "watch"}},
		{"serviceaccounts get", Request{Resource: "serviceaccounts", Verb: "get"}},
		{"watch verb is not special", Request{Resource: "secrets", Verb: "watch"}},
	}
	for _, tc := range allowed {
		t.Run("not universally denied: "+tc.name, func(t *testing.T) {
			if d := universalDenyDecision(tc.req); !d.Allow {
				t.Errorf("universalDenyDecision denied %+v: %s", tc.req, d.Reason)
			}
		})
	}
}

func TestVerbGate(t *testing.T) {
	read := []string{"get", "list", "watch"}
	write := []string{"create", "update", "patch", "delete", "deletecollection"}

	for _, v := range read {
		for _, m := range AllModes {
			if d := verbGateDecision(m, Request{Resource: "pods", Verb: v}); !d.Allow {
				t.Errorf("mode %s denied read verb %s", m, v)
			}
		}
	}
	for _, v := range write {
		for _, m := range []Mode{ModeRONoSecret, ModeROSecret} {
			if d := verbGateDecision(m, Request{Resource: "pods", Verb: v}); d.Allow {
				t.Errorf("mode %s allowed write verb %s", m, v)
			}
		}
		if d := verbGateDecision(ModeRW, Request{Resource: "pods", Verb: v}); !d.Allow {
			t.Errorf("rw denied write verb %s", v)
		}
	}
	// Unknown verbs are denied everywhere, including in rw.
	for _, v := range []string{"", "proxy", "connect", "frobnicate"} {
		for _, m := range AllModes {
			if d := verbGateDecision(m, Request{Resource: "pods", Verb: v}); d.Allow {
				t.Errorf("mode %s allowed unknown verb %q", m, v)
			}
		}
	}
}

func TestModeResourceDecision(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		req  Request
		want bool
	}{
		{"nosecret allows pods", ModeRONoSecret, Request{Resource: "pods", Verb: "get"}, true},
		{"nosecret allows pods/log", ModeRONoSecret, Request{Resource: "pods", Subresource: "log", Verb: "get"}, true},
		{"nosecret allows configmaps", ModeRONoSecret, Request{Resource: "configmaps", Verb: "list"}, true},
		{"nosecret allows core events", ModeRONoSecret, Request{Resource: "events", Verb: "list"}, true},
		{"nosecret allows events.k8s.io events", ModeRONoSecret, Request{APIGroup: "events.k8s.io", Resource: "events", Verb: "list"}, true},
		{"nosecret allows deployments", ModeRONoSecret, Request{APIGroup: "apps", Resource: "deployments", Verb: "list"}, true},
		{"nosecret allows metrics pods", ModeRONoSecret, Request{APIGroup: "metrics.k8s.io", Resource: "pods", Verb: "list"}, true},
		{"nosecret allows CRD schemas", ModeRONoSecret, Request{APIGroup: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Verb: "list"}, true},

		{"nosecret denies secrets", ModeRONoSecret, Request{Resource: "secrets", Verb: "get"}, false},
		{"nosecret denies rbac", ModeRONoSecret, Request{APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "list"}, false},
		{"nosecret denies csr", ModeRONoSecret, Request{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "list"}, false},
		{"nosecret denies webhooks", ModeRONoSecret, Request{APIGroup: "admissionregistration.k8s.io", Resource: "validatingwebhookconfigurations", Verb: "list"}, false},
		{"nosecret denies unknown CRD", ModeRONoSecret, Request{APIGroup: "example.com", Resource: "widgets", Verb: "list"}, false},
		{"nosecret denies ExternalSecret", ModeRONoSecret, Request{APIGroup: "external-secrets.io", Resource: "externalsecrets", Verb: "list"}, false},
		{"nosecret denies SealedSecret", ModeRONoSecret, Request{APIGroup: "bitnami.com", Resource: "sealedsecrets", Verb: "list"}, false},
		{"nosecret denies unlisted subresource", ModeRONoSecret, Request{APIGroup: "apps", Resource: "deployments", Subresource: "scale", Verb: "get"}, false},

		{"ro-secret allows secrets", ModeROSecret, Request{Resource: "secrets", Verb: "get"}, true},
		{"ro-secret allows unknown CRD", ModeROSecret, Request{APIGroup: "example.com", Resource: "widgets", Verb: "list"}, true},
		{"ro-secret allows rbac", ModeROSecret, Request{APIGroup: "rbac.authorization.k8s.io", Resource: "roles", Verb: "list"}, true},
		{"rw allows secrets", ModeRW, Request{Resource: "secrets", Verb: "create"}, true},
		{"rw allows rbac writes", ModeRW, Request{APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "create"}, true},
		{"rw allows unknown CRD", ModeRW, Request{APIGroup: "example.com", Resource: "widgets", Verb: "create"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := modeResourceDecision(tc.mode, nil, tc.req)
			if d.Allow != tc.want {
				t.Errorf("modeResourceDecision(%s, %+v).Allow = %v, want %v (reason=%q)",
					tc.mode, tc.req, d.Allow, tc.want, d.Reason)
			}
		})
	}
}

func TestModeResourceDecisionHonoursExtraRules(t *testing.T) {
	extra := RuleSet{{APIGroups: []string{"example.com"}, Resources: []string{"widgets"}, Verbs: []string{"get", "list", "watch"}}}
	req := Request{APIGroup: "example.com", Resource: "widgets", Verb: "list"}

	if d := modeResourceDecision(ModeRONoSecret, nil, req); d.Allow {
		t.Fatal("widgets must be denied without extra rules")
	}
	if d := modeResourceDecision(ModeRONoSecret, extra, req); !d.Allow {
		t.Fatalf("widgets must be allowed with extra rules: %s", d.Reason)
	}
	// Extra rules must not leak into a different group or resource.
	other := Request{APIGroup: "example.com", Resource: "gadgets", Verb: "list"}
	if d := modeResourceDecision(ModeRONoSecret, extra, other); d.Allow {
		t.Error("extra rules must not admit unlisted resources")
	}
}
