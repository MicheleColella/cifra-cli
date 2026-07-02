package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/MicheleColella/cifra-cli/internal/secmem"
)

// envelopeVersion is the only supported on-disk format revision.
// Future versions must be introduced as new constants; old envelopes are
// always readable by the version that sealed them.
const envelopeVersion = 1

// Recipient holds a data key encrypted for one X25519 public key.
type Recipient struct {
	EphemeralPublic []byte `json:"ephemeral_public"`
	Nonce           []byte `json:"nonce"`
	WrappedKey      []byte `json:"wrapped_key"`
}

// Envelope is the on-disk format for a sealed secret.
type Envelope struct {
	Version    int         `json:"version"`
	Suite      CipherSuite `json:"suite"`
	Nonce      []byte      `json:"nonce"`
	Ciphertext []byte      `json:"ciphertext"`
	Recipients []Recipient `json:"recipients"`
}

// Seal encrypts payload with a random data key (DEK) using suite, then wraps
// the DEK for each recipient's X25519 public key via ephemeral ECDH + HKDF.
func Seal(payload []byte, recipients []PublicKey, suite CipherSuite) (*Envelope, error) {
	if err := validateSuite(suite); err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient required")
	}

	dek, err := generateDEK()
	if err != nil {
		return nil, fmt.Errorf("generate dek: %w", err)
	}
	secmem.Lock(dek)
	defer secmem.Unlock(dek)
	defer clear(dek)

	ad := envelopeAD(envelopeVersion, suite)
	nonce, ciphertext, err := encryptPayload(payload, dek, ad, suite)
	if err != nil {
		return nil, err
	}

	recipientBlocks, err := wrapDEKForAll(dek, recipients, suite)
	if err != nil {
		return nil, err
	}

	return &Envelope{
		Version:    envelopeVersion,
		Suite:      suite,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Recipients: recipientBlocks,
	}, nil
}

// Unseal decrypts env using privateKey. It scans every recipient block (not
// just the first match) to avoid leaking the recipient's list position via
// timing. Returns the plaintext on success.
func Unseal(env *Envelope, privateKey PrivateKey) ([]byte, error) {
	if env.Version != envelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	if err := validateSuite(env.Suite); err != nil {
		return nil, err
	}

	dek, err := recoverDEK(env, privateKey)
	if err != nil {
		return nil, err
	}
	secmem.Lock(dek)
	defer secmem.Unlock(dek)
	defer clear(dek)

	aead, err := newAEAD(dek, env.Suite)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	ad := envelopeAD(env.Version, env.Suite)
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// Rewrap recovers the DEK from env using privKey, then re-wraps it for the new
// recipients. The payload ciphertext and nonce are unchanged — only the recipient
// wrapping list is replaced. Use this when adding or removing a recipient without
// re-encrypting the payload; for true revocation (new DEK + new ciphertext) use
// Seal on the decrypted plaintext instead.
func Rewrap(env *Envelope, privKey PrivateKey, recipients []PublicKey) (*Envelope, error) {
	if err := validateSuite(env.Suite); err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient required")
	}

	dek, err := recoverDEK(env, privKey)
	if err != nil {
		return nil, fmt.Errorf("recover dek: %w", err)
	}
	secmem.Lock(dek)
	defer secmem.Unlock(dek)
	defer clear(dek)

	blocks, err := wrapDEKForAll(dek, recipients, env.Suite)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, len(env.Nonce))
	copy(nonce, env.Nonce)
	ct := make([]byte, len(env.Ciphertext))
	copy(ct, env.Ciphertext)

	return &Envelope{
		Version:    env.Version,
		Suite:      env.Suite,
		Nonce:      nonce,
		Ciphertext: ct,
		Recipients: blocks,
	}, nil
}

// envelopeAD builds the authenticated-data string that binds the envelope
// metadata to the payload ciphertext.
func envelopeAD(version int, suite CipherSuite) []byte {
	return []byte(fmt.Sprintf("cifra|v%d|%s", version, suite))
}

// generateDEK returns a fresh random 32-byte data encryption key.
func generateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// encryptPayload seals payload using the DEK and returns the nonce + ciphertext.
func encryptPayload(payload, dek, ad []byte, suite CipherSuite) (nonce, ciphertext []byte, err error) {
	aead, err := newAEAD(dek, suite)
	if err != nil {
		return nil, nil, fmt.Errorf("create aead: %w", err)
	}

	nonce, err = randomNonce(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}

	return nonce, aead.Seal(nil, nonce, payload, ad), nil
}

// wrapDEKForAll encrypts dek for every recipient and returns the blocks.
func wrapDEKForAll(dek []byte, recipients []PublicKey, suite CipherSuite) ([]Recipient, error) {
	blocks := make([]Recipient, len(recipients))
	for i, pub := range recipients {
		block, err := wrapDEK(dek, pub, suite)
		if err != nil {
			return nil, fmt.Errorf("wrap key for recipient %d: %w", i, err)
		}
		blocks[i] = block
	}
	return blocks, nil
}

// wrapDEK encrypts dek for a single X25519 recipient public key using an
// ephemeral keypair. The recipient's static public key is bound into the HKDF
// info field to prevent cross-recipient key substitution.
func wrapDEK(dek []byte, recipPub PublicKey, suite CipherSuite) (Recipient, error) {
	ephPriv, ephPub, err := GenerateKeyPair()
	if err != nil {
		return Recipient{}, fmt.Errorf("generate ephemeral keypair: %w", err)
	}
	secmem.Lock(ephPriv[:])
	defer secmem.Unlock(ephPriv[:])
	defer clear(ephPriv[:]) // zero the ephemeral private scalar after ECDH

	shared, err := curve25519.X25519(ephPriv[:], recipPub[:])
	if err != nil {
		return Recipient{}, fmt.Errorf("ecdh: %w", err)
	}
	secmem.Lock(shared)
	defer secmem.Unlock(shared)
	defer clear(shared)

	wk, err := deriveWrappingKey(shared, ephPub[:], recipPub[:])
	if err != nil {
		return Recipient{}, fmt.Errorf("derive wrapping key: %w", err)
	}
	secmem.Lock(wk)
	defer secmem.Unlock(wk)
	defer clear(wk)

	aead, err := newAEAD(wk, suite)
	if err != nil {
		return Recipient{}, fmt.Errorf("create wrap aead: %w", err)
	}

	wrapNonce, err := randomNonce(aead.NonceSize())
	if err != nil {
		return Recipient{}, err
	}

	return Recipient{
		EphemeralPublic: ephPub[:],
		Nonce:           wrapNonce,
		// ephPub[:] is used as additional data to bind the wrapped key to its
		// ephemeral public key, preventing it from being transplanted to another block.
		WrappedKey: aead.Seal(nil, wrapNonce, dek, ephPub[:]),
	}, nil
}

// recoverDEK scans all recipient blocks — not just the first match — so that
// elapsed time does not reveal the matching recipient's index in the list.
func recoverDEK(env *Envelope, privateKey PrivateKey) ([]byte, error) {
	var result []byte
	for _, r := range env.Recipients {
		dek, err := tryUnwrap(r, privateKey, env.Suite)
		if err == nil && result == nil {
			result = dek
		} else if err == nil {
			clear(dek) // discard extra matches from a malformed envelope
		}
	}
	if result == nil {
		return nil, fmt.Errorf("private key does not match any recipient")
	}
	return result, nil
}

// tryUnwrap attempts to decrypt a single recipient block. It derives the
// caller's own public key from privateKey to reproduce the KDF context used
// when the block was sealed.
func tryUnwrap(r Recipient, privateKey PrivateKey, suite CipherSuite) ([]byte, error) {
	if len(r.EphemeralPublic) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key length %d", len(r.EphemeralPublic))
	}

	ownPub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive own public key: %w", err)
	}

	shared, err := curve25519.X25519(privateKey[:], r.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	secmem.Lock(shared)
	defer secmem.Unlock(shared)
	defer clear(shared)

	wk, err := deriveWrappingKey(shared, r.EphemeralPublic, ownPub)
	if err != nil {
		return nil, fmt.Errorf("derive wrapping key: %w", err)
	}
	secmem.Lock(wk)
	defer secmem.Unlock(wk)
	defer clear(wk)

	aead, err := newAEAD(wk, suite)
	if err != nil {
		return nil, fmt.Errorf("create wrap aead: %w", err)
	}

	return aead.Open(nil, r.Nonce, r.WrappedKey, r.EphemeralPublic)
}
