package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestRunRotate_NotInitialized(t *testing.T) {
	err := runRotate(t.TempDir(), "DB_PASS", newMemStore())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected not-initialized error, got %v", err)
	}
}

func TestRunRotate_SecretNotFound(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	err := runRotate(root, "MISSING", newMemStore())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestRunRotate_ProducesNewCiphertext(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "API_KEY", []byte("original-value")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	storeBefore, _ := vault.LoadStore(root)
	envBefore := storeBefore.Entries[0].Envelope

	var outBuf bytes.Buffer
	ui.Out = &outBuf

	if err := runRotate(root, "API_KEY", kc); err != nil {
		t.Fatalf("runRotate: %v", err)
	}

	storeAfter, _ := vault.LoadStore(root)
	envAfter := storeAfter.Entries[0].Envelope

	if bytes.Equal(envBefore.Ciphertext, envAfter.Ciphertext) {
		t.Error("rotate produced the same ciphertext — expected a new DEK")
	}
	if bytes.Equal(envBefore.Nonce, envAfter.Nonce) {
		t.Error("rotate produced the same nonce — expected fresh randomness")
	}

	// Value must still decrypt correctly.
	plaintext, err := envcrypto.Unseal(envAfter, priv)
	if err != nil {
		t.Fatalf("Unseal after rotate: %v", err)
	}
	if string(plaintext) != "original-value" {
		t.Errorf("value after rotate = %q, want %q", plaintext, "original-value")
	}

	if !strings.Contains(outBuf.String(), "rotated") {
		t.Errorf("missing 'rotated' in output: %q", outBuf.String())
	}
}

func TestRunRotate_PreservesCreatedAt(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "TOKEN", []byte("v1")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	storeBefore, _ := vault.LoadStore(root)
	createdAt := storeBefore.Entries[0].CreatedAt

	if err := runRotate(root, "TOKEN", kc); err != nil {
		t.Fatalf("runRotate: %v", err)
	}

	storeAfter, _ := vault.LoadStore(root)
	if !storeAfter.Entries[0].CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt changed after rotate: got %v, want %v",
			storeAfter.Entries[0].CreatedAt, createdAt)
	}
}

func TestRunRotate_NoPrivateKey(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	// Add a secret using addTestRecipient's public key (already in vault).
	// We need to add via the keychain path. Let's set up a second recipient
	// with a key we control, add the secret, then try rotate without that key.
	priv2 := addTestRecipient(t, root, "bob@example.com")
	kc := newMemStore()
	if err := kc.Seal("bob@example.com", priv2[:]); err != nil {
		t.Fatalf("kc.Seal bob: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "SECRET", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	// Use an empty keychain — no matching private key.
	err := runRotate(root, "SECRET", newMemStore())
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key' error, got %v", err)
	}
}
