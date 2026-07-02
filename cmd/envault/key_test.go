package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	envcrypto "github.com/MicheleColella/envault-cli/internal/crypto"
	"github.com/MicheleColella/envault-cli/internal/keychain"
	"github.com/MicheleColella/envault-cli/internal/ui"
	"github.com/MicheleColella/envault-cli/internal/vault"
)

// memStore is an in-memory keychain.Store used in tests.
type memStore struct {
	keys map[string][]byte
}

func newMemStore() *memStore { return &memStore{keys: make(map[string][]byte)} }

func (m *memStore) Seal(id string, key []byte) error {
	if _, ok := m.keys[id]; ok {
		return fmt.Errorf("%w: %s", keychain.ErrAlreadyExists, id)
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	m.keys[id] = cp
	return nil
}

func (m *memStore) Unseal(id string) ([]byte, error) {
	k, ok := m.keys[id]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return k, nil
}

func (m *memStore) Delete(id string) error {
	if _, ok := m.keys[id]; !ok {
		return keychain.ErrNotFound
	}
	delete(m.keys, id)
	return nil
}

// initVaultRoot creates a temp dir with an initialized vault for tests that need it.
func initVaultRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if _, err := vault.Init(root, "", false); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	return root
}

// ---- key new ----

func TestRunKeyNew_SealsPrivateKey(t *testing.T) {
	kc := newMemStore()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, t.TempDir()); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}

	sealed, err := kc.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if len(sealed) != 32 {
		t.Errorf("sealed key length = %d, want 32", len(sealed))
	}
}

func TestRunKeyNew_PrintsExpectedOutput(t *testing.T) {
	kc := newMemStore()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, t.TempDir()); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"alice@example.com",
		"sha256:",
		"X25519",
		"AES-256-GCM",
		"never written to disk",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunKeyNew_FingerprintIsHex(t *testing.T) {
	kc := newMemStore()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("bob@example.com", kc, t.TempDir()); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}

	got := out.String()
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "sha256:") {
			parts := strings.SplitN(line, "sha256:", 2)
			if len(parts) != 2 {
				t.Fatalf("unexpected fingerprint line: %q", line)
			}
			fp := strings.TrimSpace(parts[1])
			if len(fp) != 64 {
				t.Errorf("fingerprint hex length = %d, want 64: %q", len(fp), fp)
			}
			return
		}
	}
	t.Error("no fingerprint line found in output")
}

func TestRunKeyNew_DifferentKeysEachCall(t *testing.T) {
	kc1, kc2 := newMemStore(), newMemStore()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc1, t.TempDir()); err != nil {
		t.Fatalf("first runKeyNew: %v", err)
	}
	if err := runKeyNew("alice@example.com", kc2, t.TempDir()); err != nil {
		t.Fatalf("second runKeyNew: %v", err)
	}

	k1, _ := kc1.Unseal("alice@example.com")
	k2, _ := kc2.Unseal("alice@example.com")
	if bytes.Equal(k1, k2) {
		t.Error("two key generations produced identical private keys")
	}
}

func TestRunKeyNew_AlreadyExists(t *testing.T) {
	kc := newMemStore()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, t.TempDir()); err != nil {
		t.Fatalf("first runKeyNew: %v", err)
	}
	err := runKeyNew("alice@example.com", kc, t.TempDir())
	if err == nil {
		t.Fatal("expected error when key already exists")
	}
	if !errors.Is(err, keychain.ErrAlreadyExists) {
		t.Errorf("error = %v, want ErrAlreadyExists", err)
	}
}

func TestRunKeyNew_AddsRecipientWhenVaultInitialized(t *testing.T) {
	kc := newMemStore()
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, root); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}

	rs, err := vault.ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(rs) != 1 || rs[0].ID != "alice@example.com" {
		t.Errorf("expected alice in recipients, got %v", rs)
	}
}

func TestRunKeyNew_SkipsRecipientWhenVaultNotInitialized(t *testing.T) {
	kc := newMemStore()
	root := t.TempDir() // no vault

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	// Should succeed without error even though vault doesn't exist.
	if err := runKeyNew("alice@example.com", kc, root); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}
}

func TestRunKeyNew_DuplicateRecipientIsSkipped(t *testing.T) {
	kc1, kc2 := newMemStore(), newMemStore()
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc1, root); err != nil {
		t.Fatalf("first runKeyNew: %v", err)
	}
	// Second key new with same ID but different store — should not error.
	if err := runKeyNew("alice@example.com", kc2, root); err != nil {
		t.Fatalf("second runKeyNew: %v", err)
	}

	rs, _ := vault.ListRecipients(root)
	if len(rs) != 1 {
		t.Errorf("expected 1 recipient (duplicate skipped), got %d", len(rs))
	}
}

// ---- key list ----

func TestRunKeyList_Empty(t *testing.T) {
	root := initVaultRoot(t)

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyList(root); err != nil {
		t.Fatalf("runKeyList: %v", err)
	}
	if !strings.Contains(out.String(), "no recipients") {
		t.Errorf("expected 'no recipients' message, got: %s", out.String())
	}
}

func TestRunKeyList_ShowsRecipients(t *testing.T) {
	root := initVaultRoot(t)

	var pub [32]byte
	_ = vault.AddRecipient(root, vault.Recipient{ID: "alice@example.com", PublicKey: pub})

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyList(root); err != nil {
		t.Fatalf("runKeyList: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("expected alice in output, got: %s", got)
	}
	if !strings.Contains(got, "sha256:") {
		t.Errorf("expected fingerprint in output, got: %s", got)
	}
}

// ---- key export ----

func TestRunKeyExport_OutputsLine(t *testing.T) {
	kc := newMemStore()
	id := "alice@example.com"

	// Generate and seal a key.
	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := kc.Seal(id, priv[:]); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyExport(id, kc); err != nil {
		t.Fatalf("runKeyExport: %v", err)
	}

	line := strings.TrimSpace(out.String())
	parts := strings.Fields(line)
	if len(parts) != 2 {
		t.Fatalf("expected '<id> <hex>', got %q", line)
	}
	if parts[0] != id {
		t.Errorf("id = %q, want %q", parts[0], id)
	}

	keyBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	var gotPub [32]byte
	copy(gotPub[:], keyBytes)
	if gotPub != pub {
		t.Errorf("exported public key does not match original")
	}
}

func TestRunKeyExport_KeyNotFound(t *testing.T) {
	kc := newMemStore()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	err := runKeyExport("nobody@example.com", kc)
	if err == nil {
		t.Fatal("expected error for unknown id")
	}
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// ---- key import ----

func TestRunKeyImport_AddsRecipient(t *testing.T) {
	root := initVaultRoot(t)

	_, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	hexPub := hex.EncodeToString(pub[:])

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyImport(root, "alice@example.com", hexPub); err != nil {
		t.Fatalf("runKeyImport: %v", err)
	}

	rs, err := vault.ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(rs) != 1 || rs[0].ID != "alice@example.com" {
		t.Errorf("expected alice in recipients, got %v", rs)
	}
	if !strings.Contains(out.String(), "alice@example.com") {
		t.Errorf("expected success output, got: %s", out.String())
	}
}

func TestRunKeyImport_DuplicateIsSkipped(t *testing.T) {
	root := initVaultRoot(t)

	_, pub, _ := envcrypto.GenerateKeyPair()
	hexPub := hex.EncodeToString(pub[:])

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyImport(root, "alice@example.com", hexPub); err != nil {
		t.Fatalf("first runKeyImport: %v", err)
	}
	// Second import of same ID should not error.
	if err := runKeyImport(root, "alice@example.com", hexPub); err != nil {
		t.Fatalf("second runKeyImport: %v", err)
	}

	rs, _ := vault.ListRecipients(root)
	if len(rs) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(rs))
	}
}

// ---- key delete ----

func TestRunKeyDelete_RemovesFromKeychain(t *testing.T) {
	kc := newMemStore()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, t.TempDir()); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}
	if err := runKeyDelete("alice@example.com", kc, t.TempDir(), false); err != nil {
		t.Fatalf("runKeyDelete: %v", err)
	}
	if _, err := kc.Unseal("alice@example.com"); !errors.Is(err, keychain.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestRunKeyDelete_AlsoRemovesFromRecipients(t *testing.T) {
	kc := newMemStore()
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, root); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}

	rs, _ := vault.ListRecipients(root)
	if len(rs) != 1 {
		t.Fatalf("expected alice in recipients before delete, got %d", len(rs))
	}

	if err := runKeyDelete("alice@example.com", kc, root, false); err != nil {
		t.Fatalf("runKeyDelete: %v", err)
	}

	rs, _ = vault.ListRecipients(root)
	if len(rs) != 0 {
		t.Errorf("expected 0 recipients after delete, got %d", len(rs))
	}
}

func TestRunKeyDelete_KeepRecipientFlag(t *testing.T) {
	kc := newMemStore()
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runKeyNew("alice@example.com", kc, root); err != nil {
		t.Fatalf("runKeyNew: %v", err)
	}
	if err := runKeyDelete("alice@example.com", kc, root, true); err != nil {
		t.Fatalf("runKeyDelete: %v", err)
	}

	rs, _ := vault.ListRecipients(root)
	if len(rs) != 1 || rs[0].ID != "alice@example.com" {
		t.Errorf("expected alice to remain in recipients with --keep-recipient, got %v", rs)
	}
}

func TestRunKeyDelete_NotFound(t *testing.T) {
	kc := newMemStore()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	err := runKeyDelete("nobody@example.com", kc, t.TempDir(), false)
	if err == nil {
		t.Fatal("expected error for non-existent key")
	}
	if !errors.Is(err, keychain.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestRunKeyImport_RejectsLowOrderKey(t *testing.T) {
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	zeros := strings.Repeat("00", 32)
	err := runKeyImport(root, "bob@example.com", zeros)
	if err == nil {
		t.Fatal("expected error for all-zero (low-order) public key")
	}

	rs, _ := vault.ListRecipients(root)
	if len(rs) != 0 {
		t.Errorf("low-order key must not enter recipients, got %d", len(rs))
	}
}

func TestRunKeyImport_InvalidHex(t *testing.T) {
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	err := runKeyImport(root, "alice@example.com", "not-hex")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

// ---- key reseal ----

func TestRunKeyReseal_LegacyKeyBecomesRecoverableWithNewPassphrase(t *testing.T) {
	kc := newMemStore()
	priv, _, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := kc.Seal("alice@example.com", priv[:]); err != nil { // raw legacy write
		t.Fatalf("seed Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })
	t.Setenv("ENVAULT_PASSPHRASE", "new-passphrase")

	if err := runKeyReseal("alice@example.com", kc); err != nil {
		t.Fatalf("runKeyReseal: %v", err)
	}

	protected := keychain.NewProtected(kc, askPassphrase)
	got, err := protected.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal after reseal: %v", err)
	}
	if !bytes.Equal(got, priv[:]) {
		t.Fatalf("resealed key mismatch")
	}
}

func TestRunKeyReseal_PrintsExpectedOutput(t *testing.T) {
	kc := newMemStore()
	priv, _, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := kc.Seal("bob@example.com", priv[:]); err != nil {
		t.Fatalf("seed Seal: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })
	t.Setenv("ENVAULT_PASSPHRASE", "pw")

	if err := runKeyReseal("bob@example.com", kc); err != nil {
		t.Fatalf("runKeyReseal: %v", err)
	}
	if !strings.Contains(out.String(), "bob@example.com") {
		t.Errorf("expected output to mention the id, got %q", out.String())
	}
}

func TestRunKeyReseal_MissingKeyErrors(t *testing.T) {
	kc := newMemStore()
	t.Setenv("ENVAULT_PASSPHRASE", "pw")

	if err := runKeyReseal("nobody@example.com", kc); err == nil {
		t.Fatal("expected error resealing a nonexistent id")
	}
}
