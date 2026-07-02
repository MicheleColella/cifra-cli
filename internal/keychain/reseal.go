package keychain

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/MicheleColella/cifra-cli/internal/secmem"
)

// Reseal migrates the private key stored at id — whether it is still a legacy
// unencrypted blob or an existing v2 blob (e.g. sealed under an old
// passphrase) — to a fresh v2 encrypted-at-rest blob. raw must be the
// underlying OS-backend Store (as returned by New()), NOT one already wrapped
// in NewProtected — Reseal wraps it itself.
//
// Atomicity: the resealed plaintext is sealed and verified under a temporary
// id BEFORE id is touched at all — this package's Seal AEAD binds the id
// itself into the ciphertext's authenticated data (see wrapDEK-style binding
// in passphrase.go), so a resealed blob cannot simply be copied from tempID
// to id; it must be sealed again under id specifically. What the temp id
// buys is the safety property: if the final Seal(id, ...) somehow fails, a
// verified-working resealed copy still exists at tempID, so id is never left
// keyless with no working copy anywhere. Compare to the unsafe alternative
// of delete-then-seal directly on id, where a failed Seal loses the key
// outright.
func Reseal(raw Store, ask PassphraseFunc, id string) error {
	protected := NewProtected(raw, ask)

	plaintext, err := protected.Unseal(id)
	if err != nil {
		return fmt.Errorf("reseal: read current key: %w", err)
	}
	secmem.Lock(plaintext)
	defer secmem.Unlock(plaintext)
	defer clear(plaintext)

	tempID, err := reservedTempID(id)
	if err != nil {
		return fmt.Errorf("reseal: generate temp id: %w", err)
	}

	if err := protected.Seal(tempID, plaintext); err != nil {
		return fmt.Errorf("reseal: write staging blob: %w", err)
	}

	verify, err := protected.Unseal(tempID)
	if err != nil {
		_ = raw.Delete(tempID)
		return fmt.Errorf("reseal: verify staging blob: %w", err)
	}
	secmem.Lock(verify)
	defer secmem.Unlock(verify)
	defer clear(verify)
	if !bytes.Equal(plaintext, verify) {
		_ = raw.Delete(tempID)
		return fmt.Errorf("reseal: verification mismatch, aborting — original key at %q left untouched", id)
	}

	// The staging round-trip proved the passphrase and backend both work.
	// Only now do we touch the real id.
	if err := raw.Delete(id); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("reseal: delete old blob for %q: %w (a verified resealed copy remains at keychain id %q)", id, err, tempID)
	}
	if err := protected.Seal(id, plaintext); err != nil {
		return fmt.Errorf("reseal: %q has no key after delete — recover manually: a verified resealed copy of the same key remains at keychain id %q: %w", id, tempID, err)
	}
	// A failure to clean up the temp id here is not reported: id is already
	// correctly resealed, and tempID is just an inert leftover blob.
	_ = raw.Delete(tempID)
	return nil
}

// reservedTempID returns an id derived from id that is exceedingly unlikely
// to collide with a real recipient id, so Reseal's staging Seal doesn't hit
// ErrAlreadyExists against unrelated data.
func reservedTempID(id string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.reseal-tmp-%s", id, hex.EncodeToString(suffix)), nil
}
