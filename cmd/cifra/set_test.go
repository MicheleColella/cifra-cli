package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestRunSet_UpdatesExistingEntry(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	// Seal initial value via runAdd.
	if err := runAdd(root, "DB_URL", []byte("postgres://old")); err != nil {
		t.Fatalf("initial runAdd: %v", err)
	}

	// Re-seal with a new value via runAdd (set delegates to runAdd).
	if err := runAdd(root, "DB_URL", []byte("postgres://new")); err != nil {
		t.Fatalf("runAdd for update: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}

	// Exactly one entry for DB_URL (no duplicates).
	var entries []vault.Entry
	for _, e := range store.Entries {
		if e.Name == "DB_URL" && e.Kind == vault.KindEnv {
			entries = append(entries, e)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 DB_URL entry, got %d", len(entries))
	}

	plaintext, err := envcrypto.Unseal(entries[0].Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != "postgres://new" {
		t.Errorf("decrypted = %q, want postgres://new", plaintext)
	}
}

func TestRunSet_PreservesCreatedAt(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "TOKEN", []byte("v1")); err != nil {
		t.Fatalf("initial runAdd: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore after first add: %v", err)
	}
	first := findEntry(t, store, "TOKEN", vault.KindEnv)
	createdAt := first.CreatedAt

	// Update value.
	if err := runAdd(root, "TOKEN", []byte("v2")); err != nil {
		t.Fatalf("runAdd for update: %v", err)
	}

	store2, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore after second add: %v", err)
	}
	second := findEntry(t, store2, "TOKEN", vault.KindEnv)

	if !second.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt changed after update: was %v, now %v", createdAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(createdAt) {
		t.Errorf("UpdatedAt should be after CreatedAt: %v vs %v", second.UpdatedAt, createdAt)
	}
}

func TestRunSet_PlaintextNotInCiphertextFile(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "PASSWORD", []byte("super-secret-value")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, vault.DirName, "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	if bytes.Contains(raw, []byte("super-secret-value")) {
		t.Error("plaintext leaked into secrets.enc")
	}
}
