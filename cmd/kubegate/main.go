// Command kubegate proxies the Kubernetes API for a client that holds no
// cluster credentials.
//
// It runs on a host that does hold them, authorizes every request against a
// fixed capability mode, and injects the host's credentials only after the
// request has passed policy.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const usage = `kubegate proxies the Kubernetes API for a credential-less client.

Usage:
  kubegate serve --context <ctx> --mode <mode> --listen <host:port> [flags]

Modes:
  ro-nosecret   read-only, curated allowlist, secret-bearing fields redacted
  ro-secret     read-only, everything readable including secrets
  rw            read and write, minus interactive sessions and credential minting

Run "kubegate serve --help" for the full flag list.
`

func main() {
	if err := realMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kubegate: %v\n", err)
		os.Exit(1)
	}
}

func realMain(args []string) error {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("expected the 'serve' subcommand")
	}

	c, err := parseFlags(args[1:], os.Stderr)
	if err != nil {
		return err
	}
	if err := c.validate(); err != nil {
		return err
	}

	// A signal cancels the context, which triggers graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return run(ctx, c, os.Stderr)
}
