package policy

import "testing"

func testScoper() StaticScoper {
	return StaticScoper{
		"/v1/pods":                         true,
		"/v1/configmaps":                   true,
		"/v1/secrets":                      true,
		"/v1/nodes":                        false,
		"/v1/namespaces":                   false,
		"apps/v1/deployments":              true,
		"storage.k8s.io/v1/storageclasses": false,
	}
}

func TestNamespaceDecisionUnscoped(t *testing.T) {
	// With no --namespace, nothing is constrained and the scoper is never
	// consulted -- passing nil proves that.
	reqs := []Request{
		{APIVersion: "v1", Resource: "pods", Namespace: "", Verb: "list"},
		{APIVersion: "v1", Resource: "pods", Namespace: "anything", Verb: "list"},
		{APIVersion: "v1", Resource: "nodes", Namespace: "", Verb: "list"},
		{APIGroup: "example.com", APIVersion: "v1", Resource: "widgets", Namespace: "x", Verb: "list"},
	}
	for _, req := range reqs {
		if d := namespaceDecision(nil, nil, req); !d.Allow {
			t.Errorf("unscoped request %+v denied: %s", req, d.Reason)
		}
	}
}

func TestNamespaceDecisionScoped(t *testing.T) {
	allowed := []string{"app", "tools"}
	s := testScoper()

	tests := []struct {
		name string
		req  Request
		want bool
	}{
		{"in-scope namespace", Request{APIVersion: "v1", Resource: "pods", Namespace: "app", Verb: "list"}, true},
		{"second in-scope namespace", Request{APIVersion: "v1", Resource: "pods", Namespace: "tools", Verb: "list"}, true},
		{"out-of-scope namespace", Request{APIVersion: "v1", Resource: "pods", Namespace: "other", Verb: "list"}, false},
		{"empty-name namespace is not a wildcard", Request{APIVersion: "v1", Resource: "pods", Namespace: "kube-system", Verb: "list"}, false},

		// The distinction this task exists for.
		{"cluster-wide collection of namespaced resource", Request{APIVersion: "v1", Resource: "pods", Namespace: "", Verb: "list"}, false},
		{"cluster-scoped resource stays readable", Request{APIVersion: "v1", Resource: "nodes", Namespace: "", Verb: "list"}, true},
		{"namespaces resource itself is cluster-scoped", Request{APIVersion: "v1", Resource: "namespaces", Namespace: "", Verb: "list"}, true},
		{"grouped cluster-scoped resource", Request{APIGroup: "storage.k8s.io", APIVersion: "v1", Resource: "storageclasses", Namespace: "", Verb: "list"}, true},
		{"grouped namespaced resource cluster-wide", Request{APIGroup: "apps", APIVersion: "v1", Resource: "deployments", Namespace: "", Verb: "list"}, false},
		{"grouped namespaced resource in scope", Request{APIGroup: "apps", APIVersion: "v1", Resource: "deployments", Namespace: "app", Verb: "list"}, true},

		// Fail closed on anything discovery has not told us about.
		{"unknown resource with empty namespace is denied", Request{APIGroup: "example.com", APIVersion: "v1", Resource: "widgets", Namespace: "", Verb: "list"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := namespaceDecision(allowed, s, tc.req)
			if d.Allow != tc.want {
				t.Errorf("namespaceDecision(%+v).Allow = %v, want %v (reason=%q)", tc.req, d.Allow, tc.want, d.Reason)
			}
			if !d.Allow && d.Reason == "" {
				t.Error("deny must carry a reason")
			}
		})
	}
}

func TestNamespaceDecisionScopedWithNilScoper(t *testing.T) {
	// A nil scoper while scoping is active must not panic and must not
	// silently permit; it means we could not learn the resource's scope.
	d := namespaceDecision([]string{"app"}, nil, Request{APIVersion: "v1", Resource: "pods", Namespace: "", Verb: "list"})
	if d.Allow {
		t.Error("must fail closed when the resource scope is unknown")
	}
}

func TestStaticScoper(t *testing.T) {
	s := testScoper()
	if ns, known := s.IsNamespaced("", "v1", "pods"); !known || !ns {
		t.Errorf("pods: got (%v,%v), want (true,true)", ns, known)
	}
	if ns, known := s.IsNamespaced("", "v1", "nodes"); !known || ns {
		t.Errorf("nodes: got (%v,%v), want (false,true)", ns, known)
	}
	if _, known := s.IsNamespaced("example.com", "v1", "widgets"); known {
		t.Error("widgets must be unknown")
	}
}
