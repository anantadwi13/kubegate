//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// TestDiscoveryWalkClassification is the safety net for the fail-closed
// guarantee.
//
// Asserting "every resource gets a decision" would be tautological -- the
// allowlist denies unknowns by construction. What actually catches mistakes
// is checking the allowlist against reality and making the denied set
// visible:
//
//  1. every allowlist entry corresponds to something the cluster advertises,
//     catching typos and stale groups that silently deny a resource we
//     believe we permit;
//  2. every universal-denylist entry the cluster advertises is really denied,
//     so the denylist is spelled the way the cluster spells it;
//  3. monotonicity holds across modes for every advertised entry;
//  4. the full classification is written to a golden file, so a cluster
//     gaining a CRD shows up as a reviewable diff.
func TestDiscoveryWalkClassification(t *testing.T) {
	c := newCluster(t)
	c.seedFixtures(t)

	advertised := c.discoverAll(t)
	if len(advertised) < 40 {
		t.Fatalf("discovery returned only %d entries; the walk is broken", len(advertised))
	}

	engines := map[policy.Mode]*policy.Engine{}
	for _, m := range policy.AllModes {
		e, err := policy.NewEngine(policy.Config{Mode: m})
		if err != nil {
			t.Fatal(err)
		}
		engines[m] = e
	}

	// (1) Allowlist entries must exist upstream.
	//
	// Compare on group-and-resource, not the versioned key: the allowlist is
	// version-agnostic by design, so a cluster serving apps/v1 must satisfy
	// an allowlist entry of "apps/deployments".
	advertisedKeys := map[string]bool{}
	for _, r := range advertised {
		name := r.Resource
		if r.Subresource != "" {
			name += "/" + r.Subresource
		}
		advertisedKeys[r.Group+"/"+name] = true
	}
	for _, missing := range policy.RONoSecretResourceKeys() {
		// metrics.k8s.io may legitimately be absent if the metrics server
		// has not registered yet; everything else must be present.
		if strings.HasPrefix(missing, "metrics.k8s.io/") {
			continue
		}
		if !advertisedKeys[missing] {
			t.Errorf("allowlist names %q but the cluster does not advertise it; "+
				"a typo or stale group silently denies a resource we believe we permit", missing)
		}
	}

	// (2) and (3) plus the golden classification.
	lines := make([]string, 0, len(advertised))
	for _, r := range advertised {
		req := policy.Request{
			IsResourceRequest: true,
			APIGroup:          r.Group,
			APIVersion:        r.Version,
			Resource:          r.Resource,
			Subresource:       r.Subresource,
			Verb:              "get",
			Name:              "probe",
		}
		if r.Namespaced {
			req.Namespace = "app"
		}

		verdicts := make([]string, 0, len(policy.AllModes))
		prev := true
		for i, m := range policy.AllModes {
			allow := engines[m].Authorize(req).Allow
			if i > 0 && !allow && prev {
				t.Errorf("monotonicity violated for %s at mode %s", r.key(), m)
			}
			prev = allow
			verdicts = append(verdicts, fmt.Sprintf("%s=%s", m, verdictWord(allow)))
		}

		// Interactive and minting paths must be denied everywhere.
		if isUniversallyDenied(r) {
			for _, m := range policy.AllModes {
				if engines[m].Authorize(req).Allow {
					t.Errorf("%s must be denied in every mode but mode %s allowed it", r.key(), m)
				}
			}
		}

		lines = append(lines, fmt.Sprintf("%-60s %s", r.key(), strings.Join(verdicts, " ")))
	}
	sort.Strings(lines)

	golden := filepath.Join("testdata", "classification.golden")
	actual := strings.Join(lines, "\n") + "\n"

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(actual), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d entries)", golden, len(lines))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("golden file missing; run with UPDATE_GOLDEN=1 to create it: %v", err)
	}
	if string(want) != actual {
		wantLines := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
		wantSet := map[string]bool{}
		for _, l := range wantLines {
			wantSet[l] = true
		}
		gotSet := map[string]bool{}
		for _, l := range lines {
			gotSet[l] = true
		}
		var added, removed []string
		for _, l := range lines {
			if !wantSet[l] {
				added = append(added, l)
			}
		}
		for _, l := range wantLines {
			if !gotSet[l] {
				removed = append(removed, l)
			}
		}
		t.Errorf("classification changed. Review the diff carefully: a new CRD "+
			"appearing here means it is now reachable or newly denied.\n"+
			"Re-run with UPDATE_GOLDEN=1 once you have confirmed the change is intended.\n"+
			"got %d entries, want %d\nadded (%d):\n%s\nremoved (%d):\n%s",
			len(lines), len(wantLines), len(added), strings.Join(added, "\n"), len(removed), strings.Join(removed, "\n"))
	}
}

func verdictWord(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func isUniversallyDenied(r apiResource) bool {
	switch r.Subresource {
	case "exec", "attach", "portforward", "proxy":
		return true
	}
	if r.Resource == "serviceaccounts" && r.Subresource == "token" {
		return true
	}
	return false
}

type apiResource struct {
	Group       string
	Version     string
	Resource    string
	Subresource string
	Namespaced  bool
}

func (r apiResource) key() string {
	name := r.Resource
	if r.Subresource != "" {
		name += "/" + r.Subresource
	}
	return r.Group + "/" + r.Version + "/" + name
}

// discoverAll walks the cluster's discovery documents via kubectl --raw, so
// the walk sees exactly what a client would.
func (c *cluster) discoverAll(t *testing.T) []apiResource {
	t.Helper()
	var out []apiResource

	out = append(out, c.discoverGroupVersion(t, "/api/v1", "", "v1")...)

	raw, err := c.hostKubectl(t, "get", "--raw", "/apis")
	if err != nil {
		t.Fatal(err)
	}
	var groups struct {
		Groups []struct {
			Name     string `json:"name"`
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
				Version      string `json:"version"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := json.Unmarshal([]byte(raw), &groups); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			out = append(out, c.discoverGroupVersion(t, "/apis/"+v.GroupVersion, g.Name, v.Version)...)
		}
	}
	return out
}

func (c *cluster) discoverGroupVersion(t *testing.T, path, group, version string) []apiResource {
	t.Helper()
	raw, err := c.hostKubectl(t, "get", "--raw", path)
	if err != nil {
		// An aggregated API that is not ready yet must not fail the walk.
		t.Logf("skipping %s: %v", path, err)
		return nil
	}
	var list struct {
		Resources []struct {
			Name       string `json:"name"`
			Namespaced bool   `json:"namespaced"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Logf("skipping %s: %v", path, err)
		return nil
	}
	var out []apiResource
	for _, r := range list.Resources {
		name, sub, _ := strings.Cut(r.Name, "/")
		out = append(out, apiResource{
			Group: group, Version: version,
			Resource: name, Subresource: sub, Namespaced: r.Namespaced,
		})
	}
	return out
}
