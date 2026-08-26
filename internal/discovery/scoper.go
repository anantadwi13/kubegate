package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// maxDiscoveryBytes bounds a single discovery document.
const maxDiscoveryBytes = 16 << 20

// BuildScoper walks the cluster's discovery documents and records whether
// each resource is namespaced.
//
// This exists for one reason. GET /api/v1/pods (a cluster-wide collection of
// a namespaced resource, which --namespace must deny) and GET /api/v1/nodes
// (a cluster-scoped resource, which it must allow) both parse to an empty
// namespace. Only the cluster can tell us which is which.
//
// The map is built only when --namespace is set, so the default path makes
// no discovery call at all. An error here is fatal at startup rather than
// tolerated: without the map, scoping would have to deny everything.
func BuildScoper(ctx context.Context, rt http.RoundTripper, base *url.URL) (policy.StaticScoper, error) {
	c := &fetcher{rt: rt, base: base}
	out := policy.StaticScoper{}

	// Core group.
	if err := c.collect(ctx, "/api/v1", "", "v1", out); err != nil {
		return nil, err
	}

	// Grouped APIs.
	var groups struct {
		Groups []struct {
			Name     string `json:"name"`
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
				Version      string `json:"version"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := c.getJSON(ctx, "/apis", &groups); err != nil {
		return nil, err
	}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			path := "/apis/" + v.GroupVersion
			if err := c.collect(ctx, path, g.Name, v.Version, out); err != nil {
				// A single aggregated API being unavailable (a metrics
				// server that is not ready yet) must not prevent startup.
				// Resources we failed to learn about stay unknown, and
				// unknown means denied while scoping is active.
				continue
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("discovery returned no resources; refusing to start with an empty scope map")
	}
	return out, nil
}

type fetcher struct {
	rt   http.RoundTripper
	base *url.URL
}

func (f *fetcher) getJSON(ctx context.Context, path string, into any) error {
	u := *f.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.rt.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: upstream returned %s", path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// collect records one group-version's resources into out.
func (f *fetcher) collect(ctx context.Context, path, group, version string, out policy.StaticScoper) error {
	var list struct {
		Resources []struct {
			Name string `json:"name"`
			// Namespaced is a pointer so a resource entry that omits the
			// field can be told apart from one that explicitly sets it to
			// false. Go's zero value for bool is false, which is the
			// *permissive* reading here (it lets namespaceDecision allow an
			// unscoped, cluster-wide request through); silently defaulting
			// to it would fail open on a malformed or truncated discovery
			// response instead of failing closed.
			Namespaced *bool `json:"namespaced"`
		} `json:"resources"`
	}
	if err := f.getJSON(ctx, path, &list); err != nil {
		return err
	}
	for _, r := range list.Resources {
		// Skip subresource entries: policy keys the scope lookup on the
		// bare resource, since a subresource shares its parent's scope.
		if strings.Contains(r.Name, "/") {
			continue
		}
		// A resource whose scope we could not determine must not be
		// recorded at all: absence means IsNamespaced reports known=false,
		// which namespaceDecision denies while scoping is active. Recording
		// it as namespaced=false would instead be the permissive answer.
		if r.Namespaced == nil {
			continue
		}
		out[policy.ScoperKey(group, version, r.Name)] = *r.Namespaced
	}
	return nil
}
