package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// addTestRecipient generates a keypair, registers the public key as a vault
// recipient, and returns the private key so tests can unseal what was sealed.
func addTestRecipient(t *testing.T, root, id string) envcrypto.PrivateKey {
	t.Helper()
	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := vault.AddRecipient(root, vault.Recipient{ID: id, PublicKey: pub}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	return priv
}

// findEntry returns the entry with the given name and kind, or fails the test.
func findEntry(t *testing.T, s *vault.Store, name string, kind vault.EntryKind) vault.Entry {
	t.Helper()
	for _, e := range s.Entries {
		if e.Name == name && e.Kind == kind {
			return e
		}
	}
	t.Fatalf("entry %q (%s) not found in store", name, kind)
	return vault.Entry{}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestRunImport_SealsSecretsDecryptableByRecipient(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	dotenv := writeFile(t, t.TempDir(), ".env", "API_KEY=secret-123\nexport DB_URL=\"postgres://x\"\n")
	if err := runImport(root, dotenv); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(store.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(store.Entries))
	}

	apiKey := findEntry(t, store, "API_KEY", vault.KindEnv)
	plaintext, err := envcrypto.Unseal(apiKey.Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal API_KEY: %v", err)
	}
	if string(plaintext) != "secret-123" {
		t.Errorf("decrypted API_KEY = %q, want secret-123", plaintext)
	}

	dbURL := findEntry(t, store, "DB_URL", vault.KindEnv)
	if dbURL.Algorithm != envcrypto.AES256GCM {
		t.Errorf("algorithm = %q, want aes-256-gcm", dbURL.Algorithm)
	}
	if len(dbURL.Recipients) != 1 || dbURL.Recipients[0] != "alice@example.com" {
		t.Errorf("recipient set = %v", dbURL.Recipients)
	}
}

func TestRunImport_PlaintextNotInCiphertextFile(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	dotenv := writeFile(t, t.TempDir(), ".env", "API_KEY=super-secret-value\n")
	if err := runImport(root, dotenv); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, vault.DirName, "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	if bytes.Contains(raw, []byte("super-secret-value")) {
		t.Error("plaintext leaked into secrets.enc")
	}
}

func TestRunImport_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir() // no vault
	dotenv := writeFile(t, t.TempDir(), ".env", "A=b\n")

	err := runImport(root, dotenv)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunImport_RequiresRecipients(t *testing.T) {
	root := initVaultRoot(t) // vault but no recipients
	dotenv := writeFile(t, t.TempDir(), ".env", "A=b\n")

	err := runImport(root, dotenv)
	if err == nil || !strings.Contains(err.Error(), "no recipients") {
		t.Fatalf("expected 'no recipients' error, got %v", err)
	}
}

func TestRunImport_ReimportUpdatesInPlace(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	dir := t.TempDir()
	if err := runImport(root, writeFile(t, dir, "a.env", "TOKEN=v1\n")); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if err := runImport(root, writeFile(t, dir, "b.env", "TOKEN=v2\n")); err != nil {
		t.Fatalf("second import: %v", err)
	}

	store, _ := vault.LoadStore(root)
	if len(store.Entries) != 1 {
		t.Fatalf("expected 1 entry after re-import, got %d", len(store.Entries))
	}
	plaintext, err := envcrypto.Unseal(store.Entries[0].Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != "v2" {
		t.Errorf("expected updated value v2, got %q", plaintext)
	}
}
