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

func TestRunAdd_SealsAndDecryptable(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	entry := findEntry(t, store, "API_KEY", vault.KindEnv)

	plaintext, err := envcrypto.Unseal(entry.Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != "s3cr3t" {
		t.Errorf("decrypted = %q, want s3cr3t", plaintext)
	}
}

func TestRunAdd_PlaintextNotInCiphertextFile(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "TOKEN", []byte("very-secret-value")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, vault.DirName, "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	if bytes.Contains(raw, []byte("very-secret-value")) {
		t.Error("plaintext leaked into secrets.enc")
	}
}

func TestRunAdd_Idempotent(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "TOKEN", []byte("v1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := runAdd(root, "TOKEN", []byte("v2")); err != nil {
		t.Fatalf("second add: %v", err)
	}

	store, _ := vault.LoadStore(root)
	if len(store.Entries) != 1 {
		t.Fatalf("expected 1 entry after upsert, got %d", len(store.Entries))
	}

	plaintext, err := envcrypto.Unseal(store.Entries[0].Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != "v2" {
		t.Errorf("expected updated value v2, got %q", plaintext)
	}
}

func TestRunAdd_PreservesCreatedAt(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "TOKEN", []byte("v1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	store1, _ := vault.LoadStore(root)
	createdAt := findEntry(t, store1, "TOKEN", vault.KindEnv).CreatedAt

	if err := runAdd(root, "TOKEN", []byte("v2")); err != nil {
		t.Fatalf("second add: %v", err)
	}
	store2, _ := vault.LoadStore(root)
	entry2 := findEntry(t, store2, "TOKEN", vault.KindEnv)

	if !entry2.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt changed on update: got %v, want %v", entry2.CreatedAt, createdAt)
	}
}

func TestRunAdd_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir()
	err := runAdd(root, "KEY", []byte("val"))
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunAdd_RequiresRecipients(t *testing.T) {
	root := initVaultRoot(t)
	err := runAdd(root, "KEY", []byte("val"))
	if err == nil || !strings.Contains(err.Error(), "no recipients") {
		t.Fatalf("expected 'no recipients' error, got %v", err)
	}
}

func TestRunAdd_MultipleRecipients(t *testing.T) {
	root := initVaultRoot(t)
	priv1 := addTestRecipient(t, root, "alice@example.com")
	priv2 := addTestRecipient(t, root, "bob@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "SECRET", []byte("shared")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	store, _ := vault.LoadStore(root)
	entry := findEntry(t, store, "SECRET", vault.KindEnv)

	for _, priv := range []envcrypto.PrivateKey{priv1, priv2} {
		plain, err := envcrypto.Unseal(entry.Envelope, priv)
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if string(plain) != "shared" {
			t.Errorf("decrypted = %q, want shared", plain)
		}
	}
}
