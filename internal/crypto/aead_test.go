package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestNewAEAD_AES256GCM(t *testing.T) {
	key := randomKey(t)
	aead, err := newAEAD(key, AES256GCM)
	if err != nil {
		t.Fatalf("newAEAD(AES256GCM): %v", err)
	}
	if aead == nil {
		t.Fatal("newAEAD returned nil")
	}
}

func TestNewAEAD_ChaCha20Poly1305(t *testing.T) {
	key := randomKey(t)
	aead, err := newAEAD(key, ChaCha20Poly1305)
	if err != nil {
		t.Fatalf("newAEAD(ChaCha20Poly1305): %v", err)
	}
	if aead == nil {
		t.Fatal("newAEAD returned nil")
	}
}

func TestNewAEAD_UnknownSuite(t *testing.T) {
	key := randomKey(t)
	_, err := newAEAD(key, CipherSuite("bogus"))
	if err == nil {
		t.Fatal("newAEAD with unknown suite should return error")
	}
}

func TestNewAEAD_BadKeyLength(t *testing.T) {
	_, err := newAEAD([]byte("short"), AES256GCM)
	if err == nil {
		t.Fatal("newAEAD(AES256GCM) with short key should return error")
	}
}

func TestAEAD_RoundTrip_AES256GCM(t *testing.T) {
	testAEADRoundTrip(t, AES256GCM)
}

func TestAEAD_RoundTrip_ChaCha20Poly1305(t *testing.T) {
	testAEADRoundTrip(t, ChaCha20Poly1305)
}

func testAEADRoundTrip(t *testing.T, suite CipherSuite) {
	t.Helper()

	key := randomKey(t)
	aead, err := newAEAD(key, suite)
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	plaintext := []byte("hello, cifra crypto")
	ct := aead.Seal(nil, nonce, plaintext, nil)

	got, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestRandomNonce_CorrectLength(t *testing.T) {
	nonce, err := randomNonce(12)
	if err != nil {
		t.Fatalf("randomNonce: %v", err)
	}
	if len(nonce) != 12 {
		t.Fatalf("got length %d, want 12", len(nonce))
	}
}

func TestRandomNonce_DifferentEachCall(t *testing.T) {
	a, err := randomNonce(12)
	if err != nil {
		t.Fatalf("randomNonce: %v", err)
	}
	b, err := randomNonce(12)
	if err != nil {
		t.Fatalf("randomNonce: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two consecutive nonces are identical — RNG is not working")
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("generate random key: %v", err)
	}
	return key
}
