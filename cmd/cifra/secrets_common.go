package main

import (
	"errors"
	"fmt"
	"time"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/secmem"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// loadRecipientKeys reads the vault recipients and returns their public keys
// alongside their IDs (positionally aligned). It errors when the vault has no
// recipients, since there would be no one able to decrypt the sealed data.
func loadRecipientKeys(repoRoot string) ([]envcrypto.PublicKey, []string, error) {
	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return nil, nil, err
	}
	if len(recipients) == 0 {
		return nil, nil, fmt.Errorf(
			"no recipients in %s/recipients — add one with `cifra key new` or `cifra key import`",
			vault.DirName,
		)
	}

	keys := make([]envcrypto.PublicKey, len(recipients))
	ids := make([]string, len(recipients))
	for i, r := range recipients {
		keys[i] = envcrypto.PublicKey(r.PublicKey)
		ids[i] = r.ID
	}
	return keys, ids, nil
}

// loadCurrentUserKey scans vault recipients and returns the first private key
// found in the OS keychain, along with its ID. The "current user" is whoever
// has a locally-stored key that matches a vault recipient.
func loadCurrentUserKey(repoRoot string, kc keychain.Store) (envcrypto.PrivateKey, string, error) {
	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return envcrypto.PrivateKey{}, "", err
	}

	for _, r := range recipients {
		privBytes, err := kc.Unseal(r.ID)
		if errors.Is(err, keychain.ErrNotFound) {
			continue
		}
		if err != nil {
			return envcrypto.PrivateKey{}, "", fmt.Errorf("unseal key for %s: %w", r.ID, err)
		}
		// privBytes is the longest-lived heap buffer holding raw key material
		// here — priv below is a [32]byte value that gets copied out on return,
		// so locking it would protect a buffer about to be discarded anyway.
		secmem.Lock(privBytes)
		defer secmem.Unlock(privBytes)
		defer clear(privBytes) // zero the heap allocation returned by kc.Unseal
		var priv envcrypto.PrivateKey
		copy(priv[:], privBytes)
		return priv, r.ID, nil
	}

	return envcrypto.PrivateKey{}, "", fmt.Errorf(
		"no private key found in keychain for any vault recipient — add one with `cifra key new`",
	)
}

// sealEntry encrypts payload for the given recipients with AES-256-GCM and
// builds a metadata-rich vault.Entry. CreatedAt and UpdatedAt are set to now;
// Store.Upsert preserves the original CreatedAt when replacing an entry.
func sealEntry(name string, kind vault.EntryKind, payload []byte, keys []envcrypto.PublicKey, ids []string) (vault.Entry, error) {
	env, err := envcrypto.Seal(payload, keys, envcrypto.AES256GCM)
	if err != nil {
		return vault.Entry{}, err
	}

	now := time.Now().UTC()
	return vault.Entry{
		Name:       name,
		Kind:       kind,
		Algorithm:  envcrypto.AES256GCM,
		Recipients: ids,
		CreatedAt:  now,
		UpdatedAt:  now,
		Envelope:   env,
	}, nil
}
