//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// TestExecPluginCredentialPath covers the one thing k3d cannot reach: a
// kubeconfig whose credentials come from an exec plugin, which is how every
// real host kubeconfig works (aws eks get-token, gcloud, corporate SSO).
//
// The plugin emits client certificate data rather than a bearer token,
// because envtest's service-account token support varies by version and the
// test's validity should not depend on it.
func TestExecPluginCredentialPath(t *testing.T) {
	dir := t.TempDir()
	callLog := filepath.Join(dir, "calls.log")

	credential := map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind":       "ExecCredential",
		"status": map[string]any{
			"clientCertificateData": string(restCfg.CertData),
			"clientKeyData":         string(restCfg.KeyData),
		},
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(dir, "credential-plugin.sh")
	content := fmt.Sprintf(`#!/bin/sh
echo "invoked" >> %q
cat <<'CRED'
%s
CRED
`, callLog, payload)
	if err := os.WriteFile(script, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}

	kc := writeKubeconfigWith(t, func(a *clientcmdapi.AuthInfo) {
		a.Exec = &clientcmdapi.ExecConfig{
			APIVersion:      "client.authentication.k8s.io/v1",
			Command:         script,
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		}
	})

	base, token, client := startProxy(t, policy.ModeROSecret, kc, "envtest-ctx")

	code, body := get(t, client, base, token, "/api/v1/namespaces/default/configmaps")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", code, body)
	}

	// The plugin must actually have been consulted; otherwise client-go
	// found some other credential and this test proves nothing.
	raw, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatalf("credential plugin was never invoked: %v", err)
	}
	if !strings.Contains(string(raw), "invoked") {
		t.Error("credential plugin log is empty")
	}
}

// TestExecPluginFailureSurfacesAsUnavailable proves the operator gets an
// actionable error rather than a mystery, which is the whole point of
// probing credentials before binding the listener.
func TestExecPluginFailureSurfacesAsUnavailable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "broken-plugin.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'session expired' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	kc := writeKubeconfigWith(t, func(a *clientcmdapi.AuthInfo) {
		a.Exec = &clientcmdapi.ExecConfig{
			APIVersion:      "client.authentication.k8s.io/v1",
			Command:         script,
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		}
	})

	// Either construction or the probe must fail; both are acceptable, but
	// starting successfully is not.
	if err := probeOnly(kc, "envtest-ctx"); err == nil {
		t.Error("a failing credential plugin must prevent startup")
	}
}
