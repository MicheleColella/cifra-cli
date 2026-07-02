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

func TestRunPush_NotInitialized(t *testing.T) {
	err := runPush(t.TempDir())
	if err == nil {
		t.Fatal("expected error for uninitialized vault")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunPush_EmptyVault(t *testing.T) {
	repo, _ := initTestRepo(t, "alice@test.com", "Alice")
	if err := runInit(repo, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	var outBuf bytes.Buffer
	ui.Out = &outBuf
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runPush(repo); err != nil {
		t.Fatalf("runPush: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "Vault pushed") {
		t.Errorf("output missing 'Vault pushed': %q", out)
	}
	if !strings.Contains(out, "recipients") {
		t.Errorf("output missing 'recipients': %q", out)
	}
	if !strings.Contains(out, "secrets") {
		t.Errorf("output missing 'secrets': %q", out)
	}
	if !strings.Contains(out, "ciphertext only") {
		t.Errorf("output missing ciphertext notice: %q", out)
	}
}

func TestRunPush_ShowsCommitHash(t *testing.T) {
	repo, _ := initTestRepo(t, "alice@test.com", "Alice")
	if err := runInit(repo, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	var outBuf bytes.Buffer
	ui.Out = &outBuf
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runPush(repo); err != nil {
		t.Fatalf("runPush: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "commit") {
		t.Errorf("output missing commit hash line: %q", out)
	}
}

func TestRecipientSetsEqual(t *testing.T) {
	cases := []struct {
		ids     []string
		current map[string]struct{}
		want    bool
	}{
		{[]string{"a", "b"}, map[string]struct{}{"a": {}, "b": {}}, true},
		{[]string{"a"}, map[string]struct{}{"a": {}, "b": {}}, false},
		{[]string{"a", "b"}, map[string]struct{}{"a": {}}, false},
		{[]string{"a", "x"}, map[string]struct{}{"a": {}, "b": {}}, false},
		{[]string{}, map[string]struct{}{}, true},
	}
	for _, c := range cases {
		got := recipientSetsEqual(c.ids, c.current)
		if got != c.want {
			t.Errorf("recipientSetsEqual(%v, %v) = %v, want %v", c.ids, c.current, got, c.want)
		}
	}
}

func TestMaybeRewrapStore_NoEntries(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	store := &vault.Store{Version: 1, Entries: nil}
	recipients, _ := vault.ListRecipients(root)

	count, updated, err := maybeRewrapStore(root, store, recipients)
	if err != nil {
		t.Fatalf("maybeRewrapStore: %v", err)
	}
	if count != 0 {
		t.Errorf("rewrapped = %d, want 0", count)
	}
	if updated != store {
		t.Error("expected original store returned unchanged")
	}
}

func TestMaybeRewrapStore_AlreadySynced(t *testing.T) {
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

	if err := runAdd(root, "K", []byte("v")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	store, _ := vault.LoadStore(root)
	recipients, _ := vault.ListRecipients(root)

	count, updated, err := maybeRewrapStore(root, store, recipients)
	if err != nil {
		t.Fatalf("maybeRewrapStore: %v", err)
	}
	if count != 0 {
		t.Errorf("rewrapped = %d, want 0 (recipient set unchanged)", count)
	}
	if updated != store {
		t.Error("expected original store returned unchanged when already synced")
	}
}

func TestRewrapStore_AddsNewRecipient(t *testing.T) {
	// Seal a secret for alice only, then rewrapStore to add bob.
	alicePriv, alicePub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair alice: %v", err)
	}
	bobPriv, bobPub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair bob: %v", err)
	}

	env, err := envcrypto.Seal([]byte("mysecret"), []envcrypto.PublicKey{alicePub}, envcrypto.AES256GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	store := &vault.Store{
		Version: 1,
		Entries: []vault.Entry{
			{Name: "SECRET", Kind: vault.KindEnv, Recipients: []string{"alice@example.com"}, Envelope: env},
		},
	}

	count, updated, err := rewrapStore(
		store, alicePriv,
		[]envcrypto.PublicKey{alicePub, bobPub},
		[]string{"alice@example.com", "bob@example.com"},
	)
	if err != nil {
		t.Fatalf("rewrapStore: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if len(updated.Entries[0].Recipients) != 2 {
		t.Errorf("recipients = %d, want 2", len(updated.Entries[0].Recipients))
	}

	// Bob must now be able to decrypt.
	plaintext, err := envcrypto.Unseal(updated.Entries[0].Envelope, bobPriv)
	if err != nil {
		t.Fatalf("Unseal bob after rewrap: %v", err)
	}
	if string(plaintext) != "mysecret" {
		t.Errorf("bob got %q, want %q", plaintext, "mysecret")
	}
}

func TestRewrapStore_RemovesRecipient(t *testing.T) {
	// Seal for alice+bob, then rewrap for alice only.
	alicePriv, alicePub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair alice: %v", err)
	}
	_, bobPub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair bob: %v", err)
	}

	env, err := envcrypto.Seal([]byte("shared"), []envcrypto.PublicKey{alicePub, bobPub}, envcrypto.AES256GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	store := &vault.Store{
		Version: 1,
		Entries: []vault.Entry{
			{Name: "KEY", Kind: vault.KindEnv,
				Recipients: []string{"alice@example.com", "bob@example.com"},
				Envelope:   env},
		},
	}

	count, updated, err := rewrapStore(
		store, alicePriv,
		[]envcrypto.PublicKey{alicePub},
		[]string{"alice@example.com"},
	)
	if err != nil {
		t.Fatalf("rewrapStore: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if len(updated.Entries[0].Recipients) != 1 {
		t.Errorf("recipients = %d, want 1 after removal", len(updated.Entries[0].Recipients))
	}

	// Alice can still decrypt.
	plaintext, err := envcrypto.Unseal(updated.Entries[0].Envelope, alicePriv)
	if err != nil {
		t.Fatalf("Unseal alice after rewrap: %v", err)
	}
	if string(plaintext) != "shared" {
		t.Errorf("alice got %q, want %q", plaintext, "shared")
	}
}

func TestRewrapStore_SkipsAlreadySyncedEntries(t *testing.T) {
	_, alicePub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair alice: %v", err)
	}

	env, err := envcrypto.Seal([]byte("val"), []envcrypto.PublicKey{alicePub}, envcrypto.AES256GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	alicePriv, _, err := envcrypto.GenerateKeyPair() // wrong key — would fail on re-wrap
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	store := &vault.Store{
		Version: 1,
		Entries: []vault.Entry{
			{Name: "K", Kind: vault.KindEnv,
				Recipients: []string{"alice@example.com"},
				Envelope:   env},
		},
	}

	// Same recipient set — no re-wrap should happen (alicePriv is wrong but won't be used).
	count, updated, err := rewrapStore(
		store, alicePriv,
		[]envcrypto.PublicKey{alicePub},
		[]string{"alice@example.com"},
	)
	if err != nil {
		t.Fatalf("rewrapStore: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 (already synced)", count)
	}
	if updated != store {
		t.Error("expected original store returned unchanged")
	}
}

func TestRunPush_AlreadyCommitted(t *testing.T) {
	// Pushing again when nothing changed in .cifra should still succeed
	// (uses HEAD hash of existing commit).
	repo, _ := initTestRepo(t, "alice@test.com", "Alice")
	if err := runInit(repo, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	// First push commits + pushes the vault init files.
	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })
	if err := runPush(repo); err != nil {
		t.Fatalf("first runPush: %v", err)
	}

	// Second push: nothing new to commit, but should push and succeed.
	var outBuf bytes.Buffer
	ui.Out = &outBuf
	if err := runPush(repo); err != nil {
		t.Fatalf("second runPush: %v", err)
	}

	if !strings.Contains(outBuf.String(), "Vault pushed") {
		t.Errorf("second push missing 'Vault pushed': %q", outBuf.String())
	}
}
