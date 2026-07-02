package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func makeVaultedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := vault.Init(dir, "", false); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	return dir
}

func TestRunProtectAdd_AddsPattern(t *testing.T) {
	dir := makeVaultedDir(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runProtectAdd(dir, "config/secrets.json"); err != nil {
		t.Fatalf("runProtectAdd: %v", err)
	}
	patterns, _ := protect.LoadPatterns(dir)
	if len(patterns) != 1 || patterns[0] != "config/secrets.json" {
		t.Errorf("unexpected patterns: %v", patterns)
	}
}

func TestRunProtectAdd_FailsWithoutVault(t *testing.T) {
	dir := t.TempDir()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runProtectAdd(dir, "secrets.json"); err == nil {
		t.Error("expected error without vault")
	}
}

func TestRunProtectList_Empty(t *testing.T) {
	dir := makeVaultedDir(t)

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runProtectList(dir); err != nil {
		t.Fatalf("runProtectList: %v", err)
	}
	if out.Len() == 0 {
		t.Error("expected some output for empty list")
	}
}

func TestRunProtectList_ShowsPatterns(t *testing.T) {
	dir := makeVaultedDir(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	_ = protect.AddPattern(dir, "data/*.csv")
	_ = protect.AddPattern(dir, "config/")

	var out bytes.Buffer
	ui.Out = &out
	if err := runProtectList(dir); err != nil {
		t.Fatalf("runProtectList: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "data/*.csv") || !strings.Contains(output, "config/") {
		t.Errorf("patterns not shown in output: %q", output)
	}
}

func TestRunProtectRemove_RemovesPattern(t *testing.T) {
	dir := makeVaultedDir(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	_ = protect.AddPattern(dir, "config/secrets.json")
	if err := runProtectRemove(dir, "config/secrets.json"); err != nil {
		t.Fatalf("runProtectRemove: %v", err)
	}
	patterns, _ := protect.LoadPatterns(dir)
	if len(patterns) != 0 {
		t.Errorf("pattern still present after remove: %v", patterns)
	}
}

func TestRunProtectRemove_ErrNotFound(t *testing.T) {
	dir := makeVaultedDir(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runProtectRemove(dir, "nonexistent"); err == nil {
		t.Error("expected error removing nonexistent pattern")
	}
}

// --- At-rest encryption tests (v0.8.4) ---

func TestRunProtectEncrypt_DeletesPlaintext(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	// Create plaintext file.
	secret := []byte("super-secret-content")
	filePath := filepath.Join(root, "secret.pem")
	if err := os.WriteFile(filePath, secret, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runProtectEncrypt(root, filePath, kc); err != nil {
		t.Fatalf("runProtectEncrypt: %v", err)
	}

	// Original file must be gone.
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("plaintext file still exists after encrypt")
	}
}

func TestRunProtectEncrypt_NoplaintextInSecretsEnc(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	secret := []byte("PLAINTEXT_MUST_NOT_APPEAR")
	filePath := filepath.Join(root, "data.key")
	if err := os.WriteFile(filePath, secret, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runProtectEncrypt(root, filePath, kc); err != nil {
		t.Fatalf("runProtectEncrypt: %v", err)
	}

	// secrets.enc must not contain the plaintext string.
	raw, err := os.ReadFile(filepath.Join(root, ".cifra", "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc: %v", err)
	}
	if strings.Contains(string(raw), "PLAINTEXT_MUST_NOT_APPEAR") {
		t.Error("plaintext present in secrets.enc — at-rest encryption failed")
	}
}

func TestRunProtectEncrypt_DecryptableInMemory(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	secret := []byte("decryptable-secret-value")
	filePath := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(filePath, secret, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runProtectEncrypt(root, filePath, kc); err != nil {
		t.Fatalf("runProtectEncrypt: %v", err)
	}

	// Load store and find the entry.
	store, err := vault.LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	entry := findEntry(t, store, filePath, vault.KindFile)

	// Decrypt in memory — must match original.
	plaintext, err := envcrypto.Unseal(entry.Envelope, priv)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(plaintext) != string(secret) {
		t.Errorf("decrypted %q, want %q", plaintext, secret)
	}
}
