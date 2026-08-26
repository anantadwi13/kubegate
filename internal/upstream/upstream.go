// Package upstream turns a host kubeconfig into an authenticated transport
// for one specific context.
//
// All credential handling is delegated to client-go: exec-plugin invocation
// (aws eks get-token, gcloud, corporate SSO), token caching and refresh,
// client certificates, proxy-url, and TLS/SNI. kubegate never reads, logs,
// or echoes credential material -- it holds a RoundTripper, not a token.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrCredentialsUnavailable signals that the host's credentials are missing,
// expired, or rejected. Expired SSO is the single most common real-world
// failure, so callers surface a "re-run your login on the host" hint.
var ErrCredentialsUnavailable = errors.New("host credentials unavailable")

// Upstream is an authenticated route to one cluster.
type Upstream struct {
	contextName string
	base        *url.URL
	transport   http.RoundTripper
}

// New loads kubeconfigPath and selects contextName.
//
// contextName is required. Falling back to current-context would make the
// proxy's target depend on ambient state, and the whole design rests on the
// host choosing the cluster explicitly and immutably.
func New(kubeconfigPath, contextName string) (*Upstream, error) {
	if contextName == "" {
		return nil, fmt.Errorf("a context name is required; kubegate never falls back to current-context")
	}

	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loading.ExplicitPath = kubeconfigPath
	}
	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loading,
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	)

	raw, err := cfg.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	if _, ok := raw.Contexts[contextName]; !ok {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	restCfg, err := cfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building client config for context %q: %w", contextName, err)
	}
	rt, err := rest.TransportFor(restCfg)
	if err != nil {
		return nil, fmt.Errorf("building transport for context %q: %w", contextName, err)
	}
	base, err := url.Parse(restCfg.Host)
	if err != nil {
		return nil, fmt.Errorf("parsing cluster server URL: %w", err)
	}
	if base.Path == "/" {
		base.Path = ""
	}

	return &Upstream{contextName: contextName, base: base, transport: rt}, nil
}

// Transport returns the credential-injecting RoundTripper.
//
// This is the only place host credentials enter a request, and it is reached
// only after every policy check has passed.
func (u *Upstream) Transport() http.RoundTripper { return u.transport }

// BaseURL returns the cluster's scheme and host.
func (u *Upstream) BaseURL() *url.URL {
	cp := *u.base
	return &cp
}

// ContextName returns the selected context.
func (u *Upstream) ContextName() string { return u.contextName }

// Probe verifies the credentials work, by fetching /version.
//
// This runs before the listener binds, so expired SSO surfaces when the
// developer starts the proxy on the host rather than when the guest runs its
// first command. It uses the upstream transport directly and does not
// traverse the middleware chain: there is no inbound request to authorize.
func (u *Upstream) Probe(ctx context.Context) error {
	target := u.BaseURL()
	target.Path = "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := u.transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("%w: cannot reach cluster for context %q: %v", ErrCredentialsUnavailable, u.contextName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: cluster rejected the host credentials for context %q (%s)",
			ErrCredentialsUnavailable, u.contextName, resp.Status)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("cluster for context %q returned %s", u.contextName, resp.Status)
	}
	return nil
}
