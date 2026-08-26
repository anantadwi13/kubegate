// Package reqinfo turns an inbound *http.Request into a policy.Request.
//
// It delegates all parsing to the apiserver's own RequestInfoFactory. Hand
// rolling Kubernetes URL parsing is where authorization bypasses live: the
// legacy /api/v1/watch/... prefix, subresource-versus-name ambiguity,
// groupless /api versus grouped /apis, and the verb-via-path proxy form are
// all easy to get subtly wrong.
package reqinfo

import (
	"fmt"
	"net/http"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// Parser converts HTTP requests into policy inputs.
type Parser struct {
	factory *request.RequestInfoFactory
}

// New returns a Parser configured with the standard Kubernetes API prefixes.
func New() *Parser {
	return &Parser{
		factory: &request.RequestInfoFactory{
			APIPrefixes:          sets.NewString("api", "apis"),
			GrouplessAPIPrefixes: sets.NewString("api"),
		},
	}
}

// Parse produces the policy view of r.
//
// A parse error is returned rather than swallowed. The caller must treat it
// as a denial: an unparseable request is exactly the shape an attacker would
// send, and there is no safe default interpretation.
func (p *Parser) Parse(r *http.Request) (policy.Request, error) {
	info, err := p.factory.NewRequestInfo(r)
	if err != nil {
		return policy.Request{}, fmt.Errorf("parsing request path %q: %w", r.URL.Path, err)
	}
	return policy.Request{
		IsResourceRequest: info.IsResourceRequest,
		Path:              r.URL.Path,
		Verb:              info.Verb,
		APIGroup:          info.APIGroup,
		APIVersion:        info.APIVersion,
		Resource:          info.Resource,
		Subresource:       info.Subresource,
		Namespace:         info.Namespace,
		Name:              info.Name,
	}, nil
}
