//go:build darwin

package keychain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeSecurityBinary writes a shell script standing in for the real macOS
// `security` CLI, backed by a plain directory of files instead of the real
// system keychain, and prepends its directory to PATH for the test. This lets
// macos.go's exec.Command("security", ...) calls be exercised without ever
// touching the developer's actual OS keychain.
func fakeSecurityBinary(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	storeDir := t.TempDir()

	script := `#!/bin/sh
# Minimal stand-in for macOS security(1) generic-password subcommands, backed
# by files in STOREDIR instead of the real keychain. Args parsed positionally
# since cifra always calls with a fixed flag order.
cmd="$1"; shift
svc=""; acct=""; pw=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) svc="$2"; shift 2 ;;
    -a) acct="$2"; shift 2 ;;
    -w) if [ $# -ge 2 ]; then pw="$2"; shift 2; else shift; fi ;;
    *) shift ;;
  esac
done
key="$STOREDIR/$svc.$acct"
case "$cmd" in
  add-generic-password)
    if [ -f "$key" ]; then echo "already exists" >&2; exit 1; fi
    printf '%s' "$pw" > "$key"
    exit 0
    ;;
  find-generic-password)
    if [ ! -f "$key" ]; then echo "not found" >&2; exit 44; fi
    if [ -n "$WANT_W" ]; then cat "$key"; fi
    exit 0
    ;;
  delete-generic-password)
    if [ ! -f "$key" ]; then echo "not found" >&2; exit 44; fi
    rm -f "$key"
    exit 0
    ;;
  *)
    echo "unknown subcommand: $cmd" >&2
    exit 1
    ;;
esac
`
	scriptPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write fake security script: %v", err)
	}

	t.Setenv("STOREDIR", storeDir)
	t.Setenv("WANT_W", "1")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestMacOSStore_New_FindsFakeSecurityOnPath(t *testing.T) {
	fakeSecurityBinary(t)

	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestMacOSStore_SealUnsealRoundTrip(t *testing.T) {
	fakeSecurityBinary(t)
	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := []byte("thirty-two-byte-fake-private-key")
	if err := store.Seal("alice@example.com", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := store.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, key)
	}
}

func TestMacOSStore_SealAlreadyExists(t *testing.T) {
	fakeSecurityBinary(t)
	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := store.Seal("bob@example.com", []byte("key1")); err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	err = store.Seal("bob@example.com", []byte("key2"))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestMacOSStore_UnsealNotFound(t *testing.T) {
	fakeSecurityBinary(t)
	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = store.Unseal("nobody@example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMacOSStore_Delete(t *testing.T) {
	fakeSecurityBinary(t)
	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := store.Seal("carol@example.com", []byte("key")); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := store.Delete("carol@example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Unseal("carol@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestMacOSStore_DeleteNotFound(t *testing.T) {
	fakeSecurityBinary(t)
	store, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = store.Delete("nobody@example.com")
	if err == nil {
		t.Fatal("expected error deleting a nonexistent id")
	}
}

func TestMacOSStore_New_NoSecurityOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir, no "security" binary

	_, err := New()
	if !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("expected ErrNotAvailable, got %v", err)
	}
}
