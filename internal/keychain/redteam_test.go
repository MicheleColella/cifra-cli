package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// This file is the permanent red-team regression suite for internal/keychain:
// each test encodes one specific attack this package must always resist. A
// failure here means a CRITICAL flaw has been reintroduced — do not weaken
// these tests to make them pass; fix the code instead.

// TestRedTeam_KeychainExtractionYieldsOnlyV2Ciphertext restates
// TestProtectedStoresCiphertextOnly's guarantee as an explicit red-team case:
// an attacker who extracts the raw OS keychain blob (`security -w`,
// `keyctl print`, or a stolen disk image) gets only AES-256-GCM ciphertext,
// never the private key.
func TestRedTeam_KeychainExtractionYieldsOnlyV2Ciphertext(t *testing.T) {
	inner := newMemStore()
	store := NewProtected(inner, fixedPass("attacker-cannot-guess-this"))
	key := randomKey(t)

	if err := store.Seal("victim@example.com", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	extracted := inner.data["victim@example.com"]
	if bytes.Contains(extracted, key) {
		t.Fatal("RED TEAM FAIL: raw private key bytes recoverable from extracted keychain blob")
	}
	blob, kind := classifyKeyBlob(extracted)
	if kind != blobProtectedV2 {
		t.Fatalf("RED TEAM FAIL: extracted blob is not v2 ciphertext (kind=%v)", kind)
	}
	if bytes.Equal(blob.CT, key) || bytes.Contains(blob.CT, key) {
		t.Fatal("RED TEAM FAIL: ciphertext field contains the plaintext key")
	}
}

// TestRedTeam_NoDecryptionWithoutPassphrase simulates the binary running
// headless (no TTY, no CIFRA_PASSPHRASE) where PassphraseFunc itself fails —
// Unseal must propagate that failure and never return a key.
func TestRedTeam_NoDecryptionWithoutPassphrase(t *testing.T) {
	inner := newMemStore()
	sealer := NewProtected(inner, fixedPass("some-passphrase"))
	key := randomKey(t)
	if err := sealer.Seal("headless@example.com", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	noPassphrase := func(string) ([]byte, error) {
		return nil, errors.New("no passphrase available: set CIFRA_PASSPHRASE or run interactively")
	}
	store := NewProtected(inner, noPassphrase)

	got, err := store.Unseal("headless@example.com")
	if err == nil {
		t.Fatal("RED TEAM FAIL: Unseal succeeded with no passphrase available")
	}
	if got != nil {
		t.Fatal("RED TEAM FAIL: Unseal returned key material despite failing to obtain a passphrase")
	}
}

// TestRedTeam_PassphraseNeverStoredAnywhere seals several keys under a
// distinctive passphrase and confirms that exact byte sequence never appears
// in any blob the keychain (or a Reseal staging entry) ends up holding.
func TestRedTeam_PassphraseNeverStoredAnywhere(t *testing.T) {
	inner := newMemStore()
	passphrase := []byte("this-exact-string-must-never-be-persisted-anywhere")
	ask := fixedPass(string(passphrase))
	store := NewProtected(inner, ask)

	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("user%d@example.com", i)
		if err := store.Seal(id, randomKey(t)); err != nil {
			t.Fatalf("Seal(%s): %v", id, err)
		}
	}
	if err := Reseal(inner, ask, "user0@example.com"); err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	for id, blob := range inner.data {
		if bytes.Contains(blob, passphrase) {
			t.Fatalf("RED TEAM FAIL: passphrase bytes found in stored blob for %q", id)
		}
	}
}

// TestRedTeam_WrongPassphraseLeaksNothing confirms a failed decrypt attempt
// with the wrong passphrase returns neither the key nor any partial plaintext.
func TestRedTeam_WrongPassphraseLeaksNothing(t *testing.T) {
	inner := newMemStore()
	key := randomKey(t)
	if err := NewProtected(inner, fixedPass("correct")).Seal("target", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := NewProtected(inner, fixedPass("incorrect")).Unseal("target")
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
	if got != nil {
		t.Fatal("RED TEAM FAIL: wrong passphrase returned non-nil key material")
	}
	if len(got) != 0 {
		t.Fatal("RED TEAM FAIL: wrong passphrase returned partial plaintext")
	}
}
