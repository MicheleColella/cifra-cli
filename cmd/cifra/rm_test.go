package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestRunRm_RemovesEntry(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "TOKEN", []byte("secret")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	if err := runRm(root, "TOKEN"); err != nil {
		t.Fatalf("runRm: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(store.Entries) != 0 {
		t.Errorf("expected 0 entries after rm, got %d", len(store.Entries))
	}
}

func TestRunRm_ErrorWhenNotFound(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	err := runRm(root, "NONEXISTENT")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got %v", err)
	}
}

func TestRunRm_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir()
	err := runRm(root, "KEY")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunRm_OnlyRemovesNamedEntry(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "A", []byte("a")); err != nil {
		t.Fatalf("add A: %v", err)
	}
	if err := runAdd(root, "B", []byte("b")); err != nil {
		t.Fatalf("add B: %v", err)
	}
	if err := runRm(root, "A"); err != nil {
		t.Fatalf("runRm A: %v", err)
	}

	store, _ := vault.LoadStore(root)
	if len(store.Entries) != 1 {
		t.Fatalf("expected 1 entry remaining, got %d", len(store.Entries))
	}
	if store.Entries[0].Name != "B" {
		t.Errorf("remaining entry = %q, want B", store.Entries[0].Name)
	}
}
