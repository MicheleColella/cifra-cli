package keychain

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
)

// memStore is a tiny in-memory Store used to inspect exactly what bytes the
// protected decorator hands to the underlying OS keychain.
type memStore struct {
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: make(map[string][]byte)} }

func (m *memStore) Seal(id string, key []byte) error {
	if _, ok := m.data[id]; ok {
		return ErrAlreadyExists
	}
	m.data[id] = append([]byte(nil), key...)
	return nil
}

func (m *memStore) Unseal(id string) ([]byte, error) {
	v, ok := m.data[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *memStore) Delete(id string) error {
	if _, ok := m.data[id]; !ok {
		return ErrNotFound
	}
	delete(m.data, id)
	return nil
}

func fixedPass(p string) PassphraseFunc {
	return func(string) ([]byte, error) { return []byte(p), nil }
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func TestProtectedRoundTrip(t *testing.T) {
	// Arrange
	inner := newMemStore()
	store := NewProtected(inner, fixedPass("correct horse battery staple"))
	key := randomKey(t)

	// Act
	if err := store.Seal("alice@example.com", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := store.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	// Assert
	if !bytes.Equal(got, key) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, key)
	}
}

func TestProtectedWrongPassphrase(t *testing.T) {
	// Arrange
	inner := newMemStore()
	good := NewProtected(inner, fixedPass("right-passphrase"))
	key := randomKey(t)
	if err := good.Seal("bob", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Act: a decorator over the SAME inner store but with a wrong passphrase.
	bad := NewProtected(inner, fixedPass("wrong-passphrase"))
	got, err := bad.Unseal("bob")

	// Assert
	if !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected no key on wrong passphrase, got %x", got)
	}
}

// TestProtectedStoresCiphertextOnly is the core regression test guarding the
// Round 1 red-team critical: the OS keychain blob (what `security -w` /
// `keyctl print` return to ANY same-user process) must never contain the raw
// private key. If anyone reintroduces raw-key storage, this test FAILS. Do not
// weaken it.
func TestProtectedStoresCiphertextOnly(t *testing.T) {
	// Arrange
	inner := newMemStore()
	store := NewProtected(inner, fixedPass("s3cret-passphrase"))
	key := randomKey(t)

	// Act
	if err := store.Seal("carol", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Assert: the bytes the OS keychain actually holds must NOT be the key.
	stored := inner.data["carol"]
	if bytes.Equal(stored, key) {
		t.Fatal("inner store holds the raw key — encryption did not happen")
	}
	if bytes.Contains(stored, key) {
		t.Fatal("raw key bytes found inside the stored blob — leak!")
	}

	// And it must parse as a v2 protected blob whose ciphertext != plaintext.
	blob, kind := classifyKeyBlob(stored)
	if kind != blobProtectedV2 {
		t.Fatal("stored value is not a v2 protected blob")
	}
	if blob.V != protectedVersion || blob.KDF != "argon2id" {
		t.Fatalf("unexpected blob header: v=%d kdf=%q", blob.V, blob.KDF)
	}
	if bytes.Equal(blob.CT, key) {
		t.Fatal("ciphertext equals plaintext key")
	}
	if bytes.Contains(blob.CT, key) {
		t.Fatal("plaintext key found inside ciphertext")
	}
}

// TestProtectedLegacyKeyPassthrough verifies backward compatibility AND that a
// raw key from a pre-fix binary triggers the loud security warning (Round 2
// closing task): the key must still unseal, but the user must be told it is
// still extractable until they regenerate.
func TestProtectedLegacyKeyPassthrough(t *testing.T) {
	// Arrange: simulate an old vault by writing a raw key straight to inner.
	inner := newMemStore()
	key := randomKey(t)
	if err := inner.Seal("legacy", key); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}
	var warnBuf bytes.Buffer
	ui.Err = &warnBuf
	t.Cleanup(func() { ui.Err = os.Stderr })

	// Act
	store := NewProtected(inner, fixedPass("unused"))
	got, err := store.Unseal("legacy")

	// Assert: still readable (no lockout)...
	if err != nil {
		t.Fatalf("Unseal legacy: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("legacy passthrough mismatch")
	}
	// ...and the user was warned loudly on stderr.
	warned := warnBuf.String()
	if !strings.Contains(warned, "old unencrypted format") &&
		!strings.Contains(warned, "OLD unencrypted format") {
		t.Fatalf("expected legacy security warning, got %q", warned)
	}
	if !strings.Contains(warned, "legacy") {
		t.Fatalf("warning should name the key id, got %q", warned)
	}
}

// TestProtectedV2NoWarning ensures the warning fires ONLY for legacy keys, never
// for properly protected v2 blobs (no false-positive nagging).
func TestProtectedV2NoWarning(t *testing.T) {
	inner := newMemStore()
	var warnBuf bytes.Buffer
	ui.Err = &warnBuf
	t.Cleanup(func() { ui.Err = os.Stderr })

	store := NewProtected(inner, fixedPass("pw"))
	if err := store.Seal("eve", randomKey(t)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := store.Unseal("eve"); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if warnBuf.Len() != 0 {
		t.Fatalf("v2 key must not warn, got %q", warnBuf.String())
	}
}

// TestProtectedUnknownVersionErrors is the forward-compatibility guard: a key
// envelope written by a NEWER cifra (e.g. v3) must surface a clear "upgrade"
// error, never be silently misread as a legacy raw key (which would corrupt the
// key and warn with the wrong message).
func TestProtectedUnknownVersionErrors(t *testing.T) {
	inner := newMemStore()
	// Simulate a future v3 envelope landing in the keychain.
	future := []byte(`{"v":3,"kdf":"argon2id","salt":"AAAA","nonce":"AAAA","ct":"AAAA","new_field":true}`)
	if err := inner.Seal("future", future); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}
	var warnBuf bytes.Buffer
	ui.Err = &warnBuf
	t.Cleanup(func() { ui.Err = os.Stderr })

	store := NewProtected(inner, fixedPass("pw"))
	got, err := store.Unseal("future")

	if !errors.Is(err, ErrUnsupportedKeyVersion) {
		t.Fatalf("expected ErrUnsupportedKeyVersion, got %v", err)
	}
	if got != nil {
		t.Fatalf("must not return a key for an unknown version, got %x", got)
	}
	if strings.Contains(warnBuf.String(), "old unencrypted") {
		t.Fatalf("a future-version blob must not be reported as a legacy key: %q", warnBuf.String())
	}
}

// TestProtectedUnrecognizedBlobErrors ensures a blob that is neither a 32-byte
// legacy key nor our JSON envelope is rejected, never treated as key material.
func TestProtectedUnrecognizedBlobErrors(t *testing.T) {
	inner := newMemStore()
	if err := inner.Seal("garbage", []byte("this is not 32 bytes and not json envelope")); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}
	store := NewProtected(inner, fixedPass("pw"))
	got, err := store.Unseal("garbage")
	if !errors.Is(err, ErrUnsupportedKeyVersion) {
		t.Fatalf("expected ErrUnsupportedKeyVersion, got %v", err)
	}
	if got != nil {
		t.Fatalf("must not return a key for an unrecognized blob, got %x", got)
	}
}

func TestProtectedDeletePassthrough(t *testing.T) {
	inner := newMemStore()
	store := NewProtected(inner, fixedPass("pw"))
	if err := store.Seal("dan", randomKey(t)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := store.Delete("dan"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Unseal("dan"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
