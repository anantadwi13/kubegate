package policy

import "testing"

func TestRuleMatches(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		req  Request
		want bool
	}{
		{
			name: "exact group resource verb",
			rule: Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: "get"},
			want: true,
		},
		{
			name: "wrong verb does not match",
			rule: Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: "delete"},
			want: false,
		},
		{
			name: "wrong group does not match",
			rule: Rule{APIGroups: []string{"apps"}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: "get"},
			want: false,
		},
		{
			// The single most important semantic in this file.
			name: "bare resource does NOT grant its subresource",
			rule: Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Subresource: "log", Verb: "get"},
			want: false,
		},
		{
			name: "explicit subresource matches",
			rule: Rule{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Subresource: "log", Verb: "get"},
			want: true,
		},
		{
			name: "subresource rule does not match the bare resource",
			rule: Rule{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: "get"},
			want: false,
		},
		{
			name: "star subresource across any resource",
			rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*/exec"}, Verbs: []string{"*"}},
			req:  Request{APIGroup: "", Resource: "pods", Subresource: "exec", Verb: "create"},
			want: true,
		},
		{
			name: "star subresource does not match bare resource",
			rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*/exec"}, Verbs: []string{"*"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: "get"},
			want: false,
		},
		{
			// RBAC semantics: a lone "*" is broad and DOES cover subresources.
			name: "lone star resource covers subresources",
			rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			req:  Request{APIGroup: "", Resource: "pods", Subresource: "log", Verb: "get"},
			want: true,
		},
		{
			name: "empty verb matches nothing",
			rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get"}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: ""},
			want: false,
		},
		{
			// Regression test: defense-in-depth guarantee that empty Verb is always denied,
			// even if a pathological rule explicitly lists "" in Verbs.
			name: "pathological empty verb in Verbs list is still denied",
			rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{""}},
			req:  Request{APIGroup: "", Resource: "pods", Verb: ""},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Matches(tc.req); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRuleSetMatches(t *testing.T) {
	rs := RuleSet{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
	}
	if !rs.Matches(Request{APIGroup: "apps", Resource: "deployments", Verb: "list"}) {
		t.Error("expected second rule to match")
	}
	if rs.Matches(Request{APIGroup: "", Resource: "secrets", Verb: "get"}) {
		t.Error("expected no rule to match secrets")
	}
	if (RuleSet{}).Matches(Request{APIGroup: "", Resource: "pods", Verb: "get"}) {
		t.Error("empty RuleSet must match nothing")
	}
}
