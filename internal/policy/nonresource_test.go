package policy

import "testing"

func TestNonResourceDecision(t *testing.T) {
	allowed := []string{
		"/version",
		"/api",
		"/api/v1",
		"/apis",
		"/apis/apps",
		"/apis/apps/v1",
		"/apis/external-secrets.io/v1beta1",
		"/openapi/v2",
		"/openapi/v3",
		"/openapi/v3/apis/apps/v1",
	}
	for _, p := range allowed {
		t.Run("allow "+p, func(t *testing.T) {
			if d := nonResourceDecision(p); !d.Allow {
				t.Errorf("nonResourceDecision(%q) denied: %s", p, d.Reason)
			}
		})
	}

	denied := []string{
		"/logs",
		"/logs/kube-apiserver.log",
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/metrics",
		"/healthz",
		"/readyz",
		"/livez",
		"/.well-known/openid-configuration",
		"/openid/v1/jwks",
		"/",
		"",
		// Double-slash form: the spec records that this reaches us as a
		// NON-resource request. Exact matching is what denies it.
		"//api/v1//secrets",
		"/api/v1//secrets",
		// Too deep to be discovery.
		"/apis/apps/v1/deployments",
		// Trailing slashes are not the documented discovery shape.
		"/apis/apps/",
		"/api/v1/",
		// Empty segments must never be treated as a group name.
		"/apis//v1",
		"/apis/",
	}
	for _, p := range denied {
		t.Run("deny "+p, func(t *testing.T) {
			if d := nonResourceDecision(p); d.Allow {
				t.Errorf("nonResourceDecision(%q) allowed but must be denied", p)
			}
		})
	}
}

func TestNonResourceDecisionHasReason(t *testing.T) {
	d := nonResourceDecision("/metrics")
	if d.Allow {
		t.Fatal("expected deny")
	}
	if d.Reason == "" {
		t.Error("deny decisions must carry a reason")
	}
}
