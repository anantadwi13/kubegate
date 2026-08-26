package policy_test

import (
	"go/build"
	"testing"
)

// The policy package's whole value is being pure data-in/data-out. Importing
// net/http would let HTTP concerns leak into authorization decisions and
// would make the exhaustive table tests stop being exhaustive.
func TestPolicyPackageStaysPure(t *testing.T) {
	forbidden := map[string]bool{
		"net/http":                               true,
		"k8s.io/client-go/rest":                  true,
		"k8s.io/apiserver/pkg/endpoints/request": true,
	}
	pkg, err := build.Import("github.com/anantadwi13/kubegate/internal/policy", "", 0)
	if err != nil {
		t.Fatalf("importing policy package: %v", err)
	}
	for _, imp := range pkg.Imports {
		if forbidden[imp] {
			t.Errorf("internal/policy must not import %q", imp)
		}
	}
}
