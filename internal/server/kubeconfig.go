package server

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Banner is what the operator sees at startup: the posture, then a
// paste-ready guest kubeconfig.
//
// Nothing is written to a shared or guest-visible location; the operator
// wires the guest up deliberately.
func Banner(serverURL string, caPEM []byte, token, mode, contextName string) string {
	var b strings.Builder

	b.WriteString("\nkubegate is listening.\n\n")
	fmt.Fprintf(&b, "  cluster context : %s\n", contextName)
	fmt.Fprintf(&b, "  mode            : %s\n", mode)
	fmt.Fprintf(&b, "  address         : %s\n", serverURL)
	b.WriteString("\nThe VM needs no cluster credential. Save this as its kubeconfig:\n\n")

	fmt.Fprintf(&b, `apiVersion: v1
kind: Config
clusters:
  - name: kubegate
    cluster:
      server: %s
      certificate-authority-data: %s
users:
  - name: kubegate
    user:
      token: %s
contexts:
  - name: kubegate
    context:
      cluster: kubegate
      user: kubegate
current-context: kubegate
`, serverURL, base64.StdEncoding.EncodeToString(caPEM), token)

	b.WriteString("\nThen, in the VM:  export KUBECONFIG=/path/to/that/file\n\n")
	return b.String()
}
