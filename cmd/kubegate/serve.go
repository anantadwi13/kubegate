package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anantadwi13/kubegate/internal/audit"
	"github.com/anantadwi13/kubegate/internal/authn"
	"github.com/anantadwi13/kubegate/internal/discovery"
	"github.com/anantadwi13/kubegate/internal/policy"
	"github.com/anantadwi13/kubegate/internal/server"
	"github.com/anantadwi13/kubegate/internal/upstream"
)

type config struct {
	contextName string
	mode        policy.Mode
	listen      string
	namespaces  []string
	policyPath  string
	kubeconfig  string
	tlsDir      string
	tokenFile   string
	rotateToken bool
	tlsSANs     []string
	auditPath   string

	// extraRules is populated by validate() from policyPath.
	extraRules policy.RuleSet
}

// stringSlice collects a repeatable flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".kubegate"
	}
	return filepath.Join(home, ".kubegate")
}

func parseFlags(args []string, stderr io.Writer) (*config, error) {
	fs := flag.NewFlagSet("kubegate serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	c := &config{}
	var namespaces string
	var sans stringSlice

	fs.StringVar(&c.contextName, "context", "", "kubeconfig context to serve (required, immutable)")
	modeStr := fs.String("mode", "", "capability mode: ro-nosecret, ro-secret, or rw (required, immutable)")
	fs.StringVar(&c.listen, "listen", "", "address to listen on, e.g. 192.168.5.2:8443 (required)")
	fs.StringVar(&namespaces, "namespace", "", "comma-separated namespace allowlist; empty means unrestricted")
	fs.StringVar(&c.policyPath, "policy", "", "YAML file extending the ro-nosecret allowlist")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to the host kubeconfig (default: $KUBECONFIG, then ~/.kube/config)")
	fs.StringVar(&c.tlsDir, "tls-dir", defaultDir(), "directory holding the listener certificate and key")
	fs.StringVar(&c.tokenFile, "token-file", filepath.Join(defaultDir(), "token"), "file holding the proxy token")
	fs.BoolVar(&c.rotateToken, "rotate-token", false, "discard the persisted token and generate a new one")
	fs.Var(&sans, "tls-san", "additional certificate SAN; repeatable")
	fs.StringVar(&c.auditPath, "audit-log", "", "audit log file (default: stderr)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	c.mode = policy.Mode(*modeStr)
	c.tlsSANs = sans
	for _, ns := range strings.Split(namespaces, ",") {
		if trimmed := strings.TrimSpace(ns); trimmed != "" {
			c.namespaces = append(c.namespaces, trimmed)
		}
	}
	return c, nil
}

func (c *config) validate() error {
	if c.contextName == "" {
		return errors.New("--context is required; kubegate never falls back to current-context")
	}
	if _, err := policy.ParseMode(string(c.mode)); err != nil {
		return fmt.Errorf("--mode: %w", err)
	}
	if c.listen == "" {
		return errors.New("--listen is required")
	}
	if _, _, err := net.SplitHostPort(c.listen); err != nil {
		return fmt.Errorf("--listen %q is not a host:port address: %w", c.listen, err)
	}

	if c.policyPath != "" {
		if c.mode != policy.ModeRONoSecret {
			return fmt.Errorf(
				"--policy extends the %s allowlist and has no meaning in mode %s; remove the flag or switch modes",
				policy.ModeRONoSecret, c.mode)
		}
		rules, err := policy.LoadExtension(c.policyPath)
		if err != nil {
			return err
		}
		c.extraRules = rules
	}
	return nil
}

func run(ctx context.Context, c *config, stderr io.Writer) error {
	// 1. Upstream first: no point doing anything else if the credentials
	//    are dead.
	up, err := upstream.New(c.kubeconfig, c.contextName)
	if err != nil {
		return err
	}

	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := up.Probe(probeCtx); err != nil {
		if errors.Is(err, upstream.ErrCredentialsUnavailable) {
			return fmt.Errorf("%w\n\nRe-run your cluster login on the host, then start kubegate again.", err)
		}
		return err
	}

	// 2. The scope map is needed only when --namespace is set, so the
	//    default path makes no discovery call at all.
	var scoper policy.ResourceScoper
	if len(c.namespaces) > 0 {
		s, err := discovery.BuildScoper(ctx, up.Transport(), up.BaseURL())
		if err != nil {
			return fmt.Errorf("building namespace scope map: %w", err)
		}
		scoper = s
	}

	engine, err := policy.NewEngine(policy.Config{
		Mode:       c.mode,
		Namespaces: c.namespaces,
		Extra:      c.extraRules,
		Scoper:     scoper,
	})
	if err != nil {
		return err
	}

	// 3. Identity material.
	cert, caPEM, err := server.LoadOrCreateCert(c.tlsDir, c.listen, c.tlsSANs)
	if err != nil {
		return err
	}
	token, err := server.LoadOrCreateToken(c.tokenFile, c.rotateToken)
	if err != nil {
		return err
	}
	auth, err := authn.New(token)
	if err != nil {
		return err
	}

	auditOut := stderr
	if c.auditPath != "" {
		f, err := os.OpenFile(c.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("opening --audit-log: %w", err)
		}
		defer func() { _ = f.Close() }()
		auditOut = f
	}

	handler, err := server.NewHandler(server.Options{
		Upstream: up,
		Engine:   engine,
		Auth:     auth,
		Audit:    audit.NewLogger(auditOut, c.mode, c.contextName),
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:      c.listen,
		Handler:   handler,
		TLSConfig: server.TLSConfig(cert),
		// No WriteTimeout: watch and logs --follow are long-lived by
		// design, and a global write deadline would sever them.
		ReadHeaderTimeout: 30 * time.Second,
	}

	serverURL := "https://" + c.listen
	fmt.Fprint(stderr, server.Banner(serverURL, caPEM, token, string(c.mode), c.contextName))

	errCh := make(chan error, 1)
	go func() {
		// Certificates come from TLSConfig, so the paths are empty.
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
