package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/anantadwi13/kubegate/internal/policy"
)

// WriteStatus emits a Kubernetes metav1.Status body.
//
// Returning a real Status rather than a bare code is what makes kubectl
// print something useful instead of an opaque HTTP error.
func WriteStatus(w http.ResponseWriter, code int, reason, message string) {
	st := metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusFailure,
		Message:  message,
		Reason:   metav1.StatusReason(reason),
		Code:     int32(code),
	}
	body, err := json.Marshal(st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// WriteForbidden emits a denial that names the resource, the mode, and
// kubegate itself.
//
// Naming kubegate matters: without it the message is indistinguishable from
// a cluster RBAC denial, and someone will waste an afternoon editing
// ClusterRoles. Naming the mode makes the fix obvious. The upstream URL and
// all credential detail stay out; the audit log carries the rest.
func WriteForbidden(w http.ResponseWriter, req policy.Request, mode policy.Mode, why string) {
	target := req.Resource
	if req.Subresource != "" {
		target += "/" + req.Subresource
	}
	if target == "" {
		target = req.Path
	}
	msg := fmt.Sprintf("%s is forbidden: denied by kubegate policy (mode=%s): %s", target, mode, why)
	WriteStatus(w, http.StatusForbidden, string(metav1.StatusReasonForbidden), msg)
}

// WriteUnauthorized emits a 401 without hinting at what a valid token looks
// like.
func WriteUnauthorized(w http.ResponseWriter) {
	WriteStatus(w, http.StatusUnauthorized,
		string(metav1.StatusReasonUnauthorized),
		"kubegate requires a valid proxy token")
}
