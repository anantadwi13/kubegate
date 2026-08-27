package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateTokenGeneratesAndPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "token")

	tok, err := LoadOrCreateToken(p, false)
	if err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	if len(tok) < 32 {
		t.Errorf("token is only %d chars; 32 bytes of entropy should encode longer", len(tok))
	}

	again, err := LoadOrCreateToken(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if again != tok {
		t.Error("token changed across restarts; the guest kubeconfig would break")
	}
}

func TestLoadOrCreateTokenRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	first, err := LoadOrCreateToken(p, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateToken(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Error("--rotate-token must produce a new token")
	}
	third, err := LoadOrCreateToken(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Error("the rotated token must have been persisted")
	}
}

func TestLoadOrCreateTokenPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %o, want 600", perm)
	}
}

func TestLoadOrCreateTokenRejectsTruncatedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A truncated token file must not silently become the capability.
	if _, err := LoadOrCreateToken(p, false); err == nil {
		t.Error("a too-short persisted token must be rejected")
	}
}

func TestLoadOrCreateTokenTightensStalePermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	// Simulate a stale token file left over-permissive by a previous run or
	// by external tampering.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("token mode after reuse = %o, want 600; a stale over-permissive token must not silently persist", perm)
	}
}

func TestLoadOrCreateTokenTightensStaleDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	// Simulate the token's directory pre-existing (e.g. from something else,
	// or loosened between runs) with a looser mode than we'd ever create it
	// with ourselves.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "token")

	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode after create = %o, want 700; a stale over-permissive directory must not silently persist", perm)
	}

	// Loosen it again and confirm the reuse path also tightens it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	di, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode after reuse = %o, want 700; a stale over-permissive directory must not silently persist", perm)
	}
}

// TestLoadOrCreateTokenRotateTightensStalePermissions guards the rotate
// path specifically: os.WriteFile only applies its mode argument when
// CREATING a file. --rotate-token always rewrites an EXISTING token file,
// so the reuse path's chmod fix does not run here and the file could keep
// whatever looser permissions it already had.
func TestLoadOrCreateTokenRotateTightensStalePermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if _, err := LoadOrCreateToken(p, false); err != nil {
		t.Fatal(err)
	}
	// Simulate a stale token file left over-permissive by a previous run or
	// by external tampering, then rotate it.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(p, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("token mode after --rotate-token = %o, want 600; rotation must not silently keep a looser mode", perm)
	}
}

func TestTokensAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := filepath.Join(t.TempDir(), "token")
		tok, err := LoadOrCreateToken(p, false)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatal("generated a duplicate token")
		}
		seen[tok] = true
	}
}
