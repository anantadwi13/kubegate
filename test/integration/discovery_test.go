//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// installWidgetCRD creates a CRD standing in for a secret-bearing operator
// resource, so we can prove the strict mode neither serves nor advertises it.
func installWidgetCRD(t *testing.T) {
	t.Helper()
	cs, err := apiextensionsclient.NewForConfig(restCfg)
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Scope: apiextensionsv1.NamespaceScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "widgets", Singular: "widget", Kind: "Widget", ListKind: "WidgetList",
			},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"spec": {Type: "object", XPreserveUnknownFields: boolPtr(true)},
						},
					},
				},
			}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := cs.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating CRD: %v", err)
	}
	t.Cleanup(func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		_ = cs.ApiextensionsV1().CustomResourceDefinitions().Delete(delCtx, crd.Name, metav1.DeleteOptions{})
	})

	// Wait for the API to be served before asserting anything about it.
	deadline := time.Now().Add(60 * time.Second)
	established := false
	for time.Now().Before(deadline) {
		got, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crd.Name, metav1.GetOptions{})
		if err == nil {
			for _, c := range got.Status.Conditions {
				if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
					established = true
				}
			}
		}
		if established {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !established {
		t.Fatal("CRD never became Established")
	}

	// Established is necessary but not sufficient: the apiserver still has
	// to finish initializing the CR's backing storage (watch cache), and a
	// request that lands in that window gets a real, documented 429
	// ("storage is (re)initializing"). Poll the resource itself, not just
	// the CRD's status, so callers never race this warm-up window.
	waitForCRDStorageReady(t, "/apis/example.com/v1/namespaces/default/widgets")
}

// waitForCRDStorageReady polls a freshly-established CRD's resource endpoint
// directly against the apiserver (bypassing kubegate) until the apiserver
// stops answering 429 "storage is (re)initializing", confirmed live against
// envtest: Established can go true before the watch cache backing the new
// resource is ready to serve.
func waitForCRDStorageReady(t *testing.T, path string) {
	t.Helper()
	rt, err := rest.TransportFor(restCfg)
	if err != nil {
		t.Fatalf("building transport: %v", err)
	}
	client := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	host := strings.TrimSuffix(restCfg.Host, "/")

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, host+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("CRD storage never finished initializing")
}

func boolPtr(b bool) *bool { return &b }

func TestDiscoveryFilteringAgainstRealAPIServer(t *testing.T) {
	installWidgetCRD(t)
	kc := writeKubeconfig(t)

	t.Run("strict mode hides denied resources", func(t *testing.T) {
		base, token, client := startProxy(t, policy.ModeRONoSecret, kc, "envtest-ctx")

		code, body := get(t, client, base, token, "/api/v1")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		var list struct {
			Resources []struct{ Name string } `json:"resources"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatalf("filtered discovery is not valid JSON: %v", err)
		}
		names := map[string]bool{}
		for _, r := range list.Resources {
			names[r.Name] = true
		}
		if names["secrets"] {
			t.Error("strict mode must not advertise secrets")
		}
		if names["pods/exec"] {
			t.Error("strict mode must not advertise pods/exec")
		}
		if !names["pods"] || !names["configmaps"] {
			t.Errorf("strict mode dropped resources it permits: %v", names)
		}

		// The CRD's group must not appear in the group list at all.
		code, groups := get(t, client, base, token, "/apis")
		if code != http.StatusOK {
			t.Fatalf("/apis status = %d", code)
		}
		var gl struct {
			Groups []struct{ Name string } `json:"groups"`
		}
		if err := json.Unmarshal(groups, &gl); err != nil {
			t.Fatal(err)
		}
		for _, g := range gl.Groups {
			if g.Name == "example.com" {
				t.Error("strict mode must not advertise an un-opted-in CRD group")
			}
		}

		// And the instances must be denied, not merely hidden.
		if code, _ := get(t, client, base, token, "/apis/example.com/v1/namespaces/default/widgets"); code != http.StatusForbidden {
			t.Errorf("widgets: status = %d, want 403", code)
		}
	})

	t.Run("loose mode advertises and serves everything", func(t *testing.T) {
		base, token, client := startProxy(t, policy.ModeROSecret, kc, "envtest-ctx")

		code, body := get(t, client, base, token, "/api/v1")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		if !containsName(body, "secrets") {
			t.Error("ro-secret must advertise secrets")
		}
		if code, _ := get(t, client, base, token, "/apis/example.com/v1/namespaces/default/widgets"); code != http.StatusOK {
			t.Errorf("widgets: status = %d, want 200", code)
		}
	})
}

func containsName(body []byte, want string) bool {
	var list struct {
		Resources []struct{ Name string } `json:"resources"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return false
	}
	for _, r := range list.Resources {
		if r.Name == want {
			return true
		}
	}
	return false
}
