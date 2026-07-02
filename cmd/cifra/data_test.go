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

func TestRunDataStore_SealsFileDecryptableByRecipient(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	content := "-----BEGIN CERT-----\nbinary\x00data\n"
	file := writeFile(t, t.TempDir(), "cert.pem", content)

	if err := runDataStore(root, file, ""); err != nil {
		t.Fatalf("runDataStore: %v", err)
	}

	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	entry := findEntry(t, store, "cert.pem", vault.KindFile)

	plaintext, err := envcrypto.Unseal(entry.Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != content {
		t.Errorf("decrypted file mismatch")
	}
}

func TestRunDataStore_CustomName(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	file := writeFile(t, t.TempDir(), "users.csv", "a,b,c\n")
	if err := runDataStore(root, file, "internal-users"); err != nil {
		t.Fatalf("runDataStore: %v", err)
	}

	store, _ := vault.LoadStore(root)
	findEntry(t, store, "internal-users", vault.KindFile)
}

func TestRunDataStore_PlaintextNotInCiphertextFile(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	file := writeFile(t, t.TempDir(), "secret.txt", "TOP-SECRET-PAYLOAD")
	if err := runDataStore(root, file, ""); err != nil {
		t.Fatalf("runDataStore: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, vault.DirName, "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	if bytes.Contains(raw, []byte("TOP-SECRET-PAYLOAD")) {
		t.Error("plaintext leaked into secrets.enc")
	}
}

func TestRunDataStore_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir()
	file := writeFile(t, t.TempDir(), "f.txt", "x")

	err := runDataStore(root, file, "")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunDataStore_RequiresRecipients(t *testing.T) {
	root := initVaultRoot(t)
	file := writeFile(t, t.TempDir(), "f.txt", "x")

	err := runDataStore(root, file, "")
	if err == nil || !strings.Contains(err.Error(), "no recipients") {
		t.Fatalf("expected 'no recipients' error, got %v", err)
	}
}

func TestRunDataStore_MissingFile(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	err := runDataStore(root, filepath.Join(t.TempDir(), "nope.txt"), "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
