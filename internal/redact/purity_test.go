package redact_test

import (
	"go/build"
	"testing"
)

// internal/redact must stay a pure byte-transform package: no HTTP or
// client-go dependency, so it stays exhaustively table-testable and cannot
// itself become a path that reaches the upstream transport.
func TestRedactPackageStaysPure(t *testing.T) {
	forbidden := map[string]bool{
		"net/http":                               true,
		"k8s.io/client-go/rest":                  true,
		"k8s.io/apiserver/pkg/endpoints/request": true,
	}
	pkg, err := build.Import("github.com/anantadwi13/kubegate/internal/redact", "", 0)
	if err != nil {
		t.Fatalf("importing redact package: %v", err)
	}
	for _, imp := range pkg.Imports {
		if forbidden[imp] {
			t.Errorf("internal/redact must not import %q", imp)
		}
	}
}
