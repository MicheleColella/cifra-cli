package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuite selects the AEAD algorithm used for both payload and key wrapping.
type CipherSuite string

const (
	AES256GCM        CipherSuite = "aes-256-gcm"
	ChaCha20Poly1305 CipherSuite = "chacha20-poly1305"
)

// newAEAD constructs a cipher.AEAD for the given 32-byte key and suite.
func newAEAD(key []byte, suite CipherSuite) (cipher.AEAD, error) {
	switch suite {
	case AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unknown cipher suite %q", suite)
	}
}

// randomNonce reads size random bytes for use as an AEAD nonce. Every key this
// package generates (the DEK, and each per-recipient wrapping key) is used to
// encrypt exactly once, so a (key, nonce) pair can never structurally repeat
// across ciphertexts — this is a fail-fast sanity guard against a catastrophic
// RNG failure (crypto/rand returning all-zero bytes), not a defense against
// reuse across calls, which the single-use key design already rules out.
func randomNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	if bytes.Equal(nonce, make([]byte, size)) {
		return nil, fmt.Errorf("generate nonce: crypto/rand returned an all-zero nonce, refusing to use it")
	}
	return nonce, nil
}

// validateSuite returns an error if suite is not a recognised CipherSuite.
func validateSuite(suite CipherSuite) error {
	switch suite {
	case AES256GCM, ChaCha20Poly1305:
		return nil
	default:
		return fmt.Errorf("unknown cipher suite %q", suite)
	}
}
