package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/MicheleColella/cifra-cli/internal/secmem"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

// ErrBadPassphrase is returned when the supplied passphrase fails to decrypt the
// stored key (wrong passphrase or tampered/corrupted blob). It is intentionally
// distinct from ErrNotFound so callers can tell "no key" from "wrong passphrase".
var ErrBadPassphrase = errors.New("incorrect passphrase or corrupted key blob")

// ErrUnsupportedKeyVersion is returned when the keychain holds a key envelope
// written by a NEWER cifra than this binary understands (e.g. a future v3
// format), or a blob in no recognized format. Forward-compatibility guard: we
// fail loudly and actionably rather than silently misreading the bytes as a key.
var ErrUnsupportedKeyVersion = errors.New("private key was written by a newer cifra version — upgrade cifra to use it")

// protectedVersion identifies the passphrase-wrapped blob format.
const protectedVersion = 2

// Argon2id KDF parameters (RFC 9106 second-recommended profile, sized for an
// interactive CLI). Changing these breaks decryption of existing blobs, so the
// version field must be bumped if they ever change.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB → 64 MiB
	argonThreads = 4
	argonKeyLen  = 32 // AES-256
	saltLen      = 16
)

// x25519KeyLen is the size of a legacy (unprotected) private key blob.
const x25519KeyLen = 32

// PassphraseFunc obtains the passphrase used to wrap/unwrap the private key.
// prompt is a human-readable hint describing why the passphrase is needed.
type PassphraseFunc func(prompt string) ([]byte, error)

// protectedBlob is the versioned, self-describing on-disk (in-keychain) format.
// Only ciphertext, salt and nonce are stored — never the passphrase or the key.
type protectedBlob struct {
	V     int    `json:"v"`     // format version (2)
	KDF   string `json:"kdf"`   // "argon2id"
	Salt  []byte `json:"salt"`  // random per-key Argon2 salt
	Nonce []byte `json:"nonce"` // random AES-GCM nonce
	CT    []byte `json:"ct"`    // AES-256-GCM(privateKey)
}

// protectedStore decorates an inner Store, encrypting key material with a
// passphrase-derived KEK before it ever reaches the OS secret store. A silently
// exfiltrated keychain blob is therefore useless ciphertext without the
// passphrase, which is never written to disk.
type protectedStore struct {
	inner Store
	ask   PassphraseFunc
}

// NewProtected wraps inner so that every Seal encrypts the private key under a
// passphrase-derived key (Argon2id → AES-256-GCM) and every Unseal decrypts it.
// Legacy unprotected blobs (raw 32-byte keys from older versions) are still
// readable, but new writes always use the protected format.
func NewProtected(inner Store, ask PassphraseFunc) Store {
	return &protectedStore{inner: inner, ask: ask}
}

// Seal derives a KEK from a passphrase and stores AES-256-GCM ciphertext of
// privateKey in the inner store. The passphrase, KEK and plaintext key are all
// zeroized before returning.
func (p *protectedStore) Seal(id string, privateKey []byte) error {
	pass, err := p.ask("Set a passphrase to protect the private key for " + id)
	if err != nil {
		return err
	}
	secmem.Lock(pass)
	defer secmem.Unlock(pass)
	defer clear(pass)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	kek := argon2.IDKey(pass, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	secmem.Lock(kek)
	defer secmem.Unlock(kek)
	defer clear(kek)

	gcm, err := newGCM(kek)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, privateKey, []byte(id))

	blob, err := json.Marshal(protectedBlob{
		V:     protectedVersion,
		KDF:   "argon2id",
		Salt:  salt,
		Nonce: nonce,
		CT:    ct,
	})
	if err != nil {
		return fmt.Errorf("marshal protected key: %w", err)
	}

	return p.inner.Seal(id, blob)
}

// Unseal reads the blob from the inner store and returns the raw private key.
// v2 blobs are decrypted with a passphrase-derived KEK; legacy raw keys are
// returned as-is for backward compatibility.
func (p *protectedStore) Unseal(id string) ([]byte, error) {
	raw, err := p.inner.Unseal(id)
	if err != nil {
		return nil, err
	}

	blob, kind := classifyKeyBlob(raw)
	switch kind {
	case blobLegacyRaw:
		// Legacy unprotected key (raw 32 bytes) from a pre-fix binary. Return it
		// transparently so old vaults keep working, but warn LOUDLY: this blob is
		// still extractable by any local process (`security -w` / `keyctl print`),
		// i.e. the Round 1 critical is NOT closed for this user until they reseal.
		// Warning goes to stderr (ui.Err) so it never corrupts piped plaintext
		// from cat/export/run.
		warnLegacyKey(id)
		return raw, nil
	case blobUnsupported:
		// Our envelope but an unknown/newer version, or an unrecognized blob.
		// Never silently treat it as a key — that would yield a corrupted key and
		// a misleading "old format" warning. Tell the user to upgrade.
		return nil, ErrUnsupportedKeyVersion
	}

	pass, err := p.ask("Enter the passphrase for the private key of " + id)
	if err != nil {
		return nil, err
	}
	secmem.Lock(pass)
	defer secmem.Unlock(pass)
	defer clear(pass)

	kek := argon2.IDKey(pass, blob.Salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	secmem.Lock(kek)
	defer secmem.Unlock(kek)
	defer clear(kek)

	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(blob.Nonce) != gcm.NonceSize() {
		return nil, ErrBadPassphrase
	}

	key, err := gcm.Open(nil, blob.Nonce, blob.CT, []byte(id))
	if err != nil {
		// Wrong passphrase or tampered blob — never leak which.
		return nil, ErrBadPassphrase
	}
	// key is the decrypted private key handed back to the caller (which owns
	// clearing it, per the Zeroization invariant) — lock it here since it's
	// the longest-lived plaintext buffer this function produces.
	secmem.Lock(key)
	return key, nil
}

// Delete passes through to the inner store.
func (p *protectedStore) Delete(id string) error {
	return p.inner.Delete(id)
}

// blobKind classifies a blob read from the inner keychain store so Unseal can
// dispatch: decrypt it, pass a legacy key through, or fail forward-compatibly.
type blobKind int

const (
	// blobProtectedV2 is the current passphrase-wrapped format (decrypt it).
	blobProtectedV2 blobKind = iota
	// blobLegacyRaw is a raw 32-byte key from a pre-protection binary (pass through + warn).
	blobLegacyRaw
	// blobUnsupported is our envelope at an unknown/newer version, or an
	// unrecognized blob — never to be interpreted as a key.
	blobUnsupported
)

// classifyKeyBlob determines how to interpret raw. It distinguishes three cases
// so that a future on-disk format (e.g. v3) is reported as "upgrade cifra"
// instead of being silently misread as a legacy raw key.
func classifyKeyBlob(raw []byte) (protectedBlob, blobKind) {
	// A legacy key is exactly 32 random bytes — treat by length first so a key
	// that happens to look like JSON is never misclassified.
	if len(raw) == x25519KeyLen {
		return protectedBlob{}, blobLegacyRaw
	}
	// Otherwise it must be our JSON envelope; probe the version first.
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return protectedBlob{}, blobUnsupported // not 32 bytes and not our JSON
	}
	if probe.V != protectedVersion {
		return protectedBlob{}, blobUnsupported // newer/unknown envelope version
	}
	var blob protectedBlob
	if err := json.Unmarshal(raw, &blob); err != nil || len(blob.Salt) == 0 || len(blob.CT) == 0 {
		return protectedBlob{}, blobUnsupported // malformed v2 envelope
	}
	return blob, blobProtectedV2
}

// warnLegacyKey prints a security warning to stderr (ui.Err) when a key is still
// stored in the pre-fix unencrypted format. It uses ui.Err directly (not ui.Warn,
// which writes to stdout) so the warning never pollutes piped secret output.
func warnLegacyKey(id string) {
	_, _ = fmt.Fprintf(ui.Err,
		"! private key for %s is stored in the OLD unencrypted format and can be "+
			"extracted by any local process — regenerate it (`cifra key delete --id %s` "+
			"then `cifra key new --id %s`) to encrypt it at rest\n",
		id, id, id)
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}
	return gcm, nil
}
