package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// tokenBytes is the raw entropy behind the proxy token.
const tokenBytes = 32

// minPersistedToken guards against a truncated file being adopted as the
// capability.
const minPersistedToken = 32

// LoadOrCreateToken returns the proxy token, generating and persisting one on
// first run.
//
// Persistence matters for usability: the guest's kubeconfig embeds this
// token, so a restart must not invalidate it. rotate discards the old value
// deliberately, which is how you revoke access.
func LoadOrCreateToken(path string, rotate bool) (string, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("creating token directory: %w", err)
		}
		// MkdirAll only applies the mode to components it actually creates,
		// so a pre-existing (or since-loosened) directory would otherwise
		// keep whatever mode it already had; tighten it explicitly.
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", fmt.Errorf("securing token directory: %w", err)
		}
	}

	if !rotate {
		if raw, err := os.ReadFile(path); err == nil {
			tok := strings.TrimSpace(string(raw))
			if len(tok) < minPersistedToken {
				return "", fmt.Errorf(
					"persisted token in %s is only %d characters; delete it or pass --rotate-token", path, len(tok))
			}
			// A stale token file from a previous run (or external tampering)
			// may be more permissive than we'd ever write ourselves; tighten
			// it rather than silently trusting whatever mode is already on
			// disk.
			if err := os.Chmod(path, 0o600); err != nil {
				return "", fmt.Errorf("securing persisted token: %w", err)
			}
			return tok, nil
		}
	}

	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing token to %s: %w", path, err)
	}
	// os.WriteFile only applies its mode argument when CREATING a file; on
	// --rotate-token this call overwrites a token file that already
	// exists, so without an explicit chmod the rotated token could
	// silently keep whatever looser permissions the old file had.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("securing token at %s: %w", path, err)
	}
	return tok, nil
}
