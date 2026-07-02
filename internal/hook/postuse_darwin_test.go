//go:build darwin

package hook

import (
	"os"
	"path/filepath"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// fakeSecurityBinary stands in for the real macOS `security` CLI so
// findMaskingKey's CIFRA_PASSPHRASE fallback (keychain.New -> the real OS
// backend) can be exercised end to end without touching the developer's
// actual OS keychain. Mirrors internal/keychain's own fake-security test
// fixture — kept local since it can't be shared across package boundaries
// without exporting a test-only helper.
func fakeSecurityBinary(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	storeDir := t.TempDir()

	script := `#!/bin/sh
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
    cat "$key"
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
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestFindMaskingKey_PassphraseFallbackSucceeds(t *testing.T) {
	withTestAgentSocket(t) // no agent listening — forces the passphrase path
	fakeSecurityBinary(t)
	t.Setenv("CIFRA_PASSPHRASE", "the-passphrase")

	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kc, err := keychain.New()
	if err != nil {
		t.Fatalf("keychain.New: %v", err)
	}
	protected := keychain.NewProtected(kc, func(string) ([]byte, error) {
		return []byte("the-passphrase"), nil
	})
	const id = "dave@example.com"
	if err := protected.Seal(id, priv[:]); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, ok := findMaskingKey([]vault.Recipient{{ID: id, PublicKey: pub}})
	if !ok {
		t.Fatal("expected findMaskingKey to succeed via the passphrase fallback")
	}
	if got != priv {
		t.Fatal("recovered key does not match the sealed private key")
	}
}
