package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/anantadwi13/kubegate/internal/policy"
)

func fakeAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("/api", func(w http.ResponseWriter, _ *http.Request) {
		write(w, `{"kind":"APIVersions","versions":["v1"]}`)
	})
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, _ *http.Request) {
		write(w, `{"kind":"APIResourceList","groupVersion":"v1","resources":[
			{"name":"pods","namespaced":true},
			{"name":"pods/log","namespaced":true},
			{"name":"nodes","namespaced":false}]}`)
	})
	mux.HandleFunc("/apis", func(w http.ResponseWriter, _ *http.Request) {
		write(w, `{"kind":"APIGroupList","groups":[
			{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}]},
			{"name":"storage.k8s.io","versions":[{"groupVersion":"storage.k8s.io/v1","version":"v1"}]}]}`)
	})
	mux.HandleFunc("/apis/apps/v1", func(w http.ResponseWriter, _ *http.Request) {
		write(w, `{"kind":"APIResourceList","groupVersion":"apps/v1","resources":[
			{"name":"deployments","namespaced":true}]}`)
	})
	mux.HandleFunc("/apis/storage.k8s.io/v1", func(w http.ResponseWriter, _ *http.Request) {
		write(w, `{"kind":"APIResourceList","groupVersion":"storage.k8s.io/v1","resources":[
			{"name":"storageclasses","namespaced":false}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildScoper(t *testing.T) {
	srv := fakeAPIServer(t)
	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s, err := BuildScoper(context.Background(), http.DefaultTransport, base)
	if err != nil {
		t.Fatalf("BuildScoper: %v", err)
	}

	cases := []struct {
		group, version, resource string
		wantNamespaced           bool
	}{
		{"", "v1", "pods", true},
		{"", "v1", "nodes", false},
		{"apps", "v1", "deployments", true},
		{"storage.k8s.io", "v1", "storageclasses", false},
	}
	for _, tc := range cases {
		ns, known := s.IsNamespaced(tc.group, tc.version, tc.resource)
		if !known {
			t.Errorf("%s/%s/%s not found in scoper", tc.group, tc.version, tc.resource)
			continue
		}
		if ns != tc.wantNamespaced {
			t.Errorf("%s/%s/%s namespaced = %v, want %v", tc.group, tc.version, tc.resource, ns, tc.wantNamespaced)
		}
	}

	// Subresources are recorded under their bare resource name only; policy
	// keys on Resource, never on Resource/Subresource.
	if _, known := s.IsNamespaced("", "v1", "pods/log"); known {
		t.Error("subresource entries must not be recorded as resources")
	}
	if _, known := s.IsNamespaced("example.com", "v1", "widgets"); known {
		t.Error("a resource the cluster never advertised must be unknown")
	}
}

func TestBuildScoperReturnsPolicyCompatibleType(t *testing.T) {
	srv := fakeAPIServer(t)
	base, _ := url.Parse(srv.URL)
	s, err := BuildScoper(context.Background(), http.DefaultTransport, base)
	if err != nil {
		t.Fatal(err)
	}
	var _ policy.ResourceScoper = s
}

func TestBuildScoperFailsOnUnreachableServer(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:1")
	if _, err := BuildScoper(context.Background(), http.DefaultTransport, base); err == nil {
		t.Error("an unreachable apiserver must be an error, not an empty scoper")
	}
}
