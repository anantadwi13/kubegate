package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExtensionValid(t *testing.T) {
	p := writeTemp(t, `
rules:
  - apiGroups: ["example.com"]
    resources: ["widgets", "widgets/status"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["monitoring.coreos.com"]
    resources: ["servicemonitors"]
    verbs: ["get"]
`)
	rs, err := LoadExtension(p)
	if err != nil {
		t.Fatalf("LoadExtension: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs))
	}
	if !rs.Matches(Request{APIGroup: "example.com", Resource: "widgets", Verb: "list"}) {
		t.Error("loaded rules must match widgets")
	}
	if !rs.Matches(Request{APIGroup: "example.com", Resource: "widgets", Subresource: "status", Verb: "get"}) {
		t.Error("loaded rules must match widgets/status")
	}
}

func TestLoadExtensionErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "wildcard api group",
			content: "rules:\n  - apiGroups: [\"*\"]\n    resources: [\"widgets\"]\n    verbs: [\"get\"]\n",
			wantErr: "wildcard",
		},
		{
			name:    "wildcard resource",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"*\"]\n    verbs: [\"get\"]\n",
			wantErr: "wildcard",
		},
		{
			name:    "wildcard subresource",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"widgets/*\"]\n    verbs: [\"get\"]\n",
			wantErr: "wildcard",
		},
		{
			name:    "wildcard verb",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"widgets\"]\n    verbs: [\"*\"]\n",
			wantErr: "verb",
		},
		{
			name:    "write verb",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"widgets\"]\n    verbs: [\"create\"]\n",
			wantErr: "verb",
		},
		{
			name:    "secrets",
			content: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"secrets\"]\n    verbs: [\"get\"]\n",
			wantErr: "secrets",
		},
		{
			name:    "rbac group",
			content: "rules:\n  - apiGroups: [\"rbac.authorization.k8s.io\"]\n    resources: [\"roles\"]\n    verbs: [\"get\"]\n",
			wantErr: "rbac.authorization.k8s.io",
		},
		{
			name:    "universally denied subresource",
			content: "rules:\n  - apiGroups: [\"\"]\n    resources: [\"pods/exec\"]\n    verbs: [\"get\"]\n",
			wantErr: "never forwarded",
		},
		{
			name:    "empty api groups",
			content: "rules:\n  - apiGroups: []\n    resources: [\"widgets\"]\n    verbs: [\"get\"]\n",
			wantErr: "apiGroups",
		},
		{
			name:    "empty resources",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: []\n    verbs: [\"get\"]\n",
			wantErr: "resources",
		},
		{
			name:    "empty verbs",
			content: "rules:\n  - apiGroups: [\"example.com\"]\n    resources: [\"widgets\"]\n    verbs: []\n",
			wantErr: "verbs",
		},
		{
			name:    "no rules at all",
			content: "rules: []\n",
			wantErr: "no rules",
		},
		{
			name:    "unknown top-level field",
			content: "rules: []\ndeny: [\"everything\"]\n",
			wantErr: "deny",
		},
		{
			name:    "malformed yaml",
			content: "rules: [oh dear\n",
			wantErr: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadExtension(writeTemp(t, tc.content))
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadExtensionMissingFile(t *testing.T) {
	if _, err := LoadExtension(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing --policy file must be an error, not an empty rule set")
	}
}
