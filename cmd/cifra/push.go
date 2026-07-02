package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newPushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push",
		Short: "Push the encrypted vault to the Git remote",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runPush(wd)
		},
	}
}

func runPush(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return err
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	// Re-wrap all entries to match the current recipient set before committing.
	rewrapped, store, err := maybeRewrapStore(repoRoot, store, recipients)
	if err != nil {
		return err
	}
	if rewrapped > 0 {
		if err := vault.SaveStore(repoRoot, store); err != nil {
			return fmt.Errorf("save rewrapped store: %w", err)
		}
	}

	hash, commitErr := git.CommitVault(repoRoot)
	if commitErr != nil && !errors.Is(commitErr, git.ErrNothingToCommit) {
		return commitErr
	}

	if errors.Is(commitErr, git.ErrNothingToCommit) {
		// No new commit — resolve HEAD so we can still report a hash.
		hash, err = git.HeadHash(repoRoot)
		if err != nil {
			hash = ""
		}
	}

	if err := git.PushOrigin(repoRoot); err != nil {
		return err
	}

	ui.OK("Vault pushed")
	ui.Info(fmt.Sprintf("recipients  %d", len(recipients)))
	ui.Info(fmt.Sprintf("secrets     %d", len(store.Entries)))
	if rewrapped > 0 {
		ui.Info(fmt.Sprintf("rewrapped   %d (recipient set changed)", rewrapped))
	}
	if hash != "" {
		ui.Info(fmt.Sprintf("commit      %s", hash))
	}
	ui.Info("GitHub stores ciphertext only — private keys never leave this machine.")
	return nil
}

// maybeRewrapStore checks whether any entry's recipient set differs from the
// current vault recipients and, if so, opens the OS keychain and re-wraps
// those entries in-place. Returns the number of re-wrapped entries and the
// (possibly updated) store. The original store is returned unchanged when no
// re-wrapping is needed, avoiding any keychain access.
func maybeRewrapStore(repoRoot string, store *vault.Store, recipients []vault.Recipient) (int, *vault.Store, error) {
	if len(store.Entries) == 0 {
		return 0, store, nil
	}

	keys := make([]envcrypto.PublicKey, len(recipients))
	ids := make([]string, len(recipients))
	idSet := make(map[string]struct{}, len(recipients))
	for i, r := range recipients {
		keys[i] = envcrypto.PublicKey(r.PublicKey)
		ids[i] = r.ID
		idSet[r.ID] = struct{}{}
	}

	if !rewrapNeeded(store, idSet) {
		return 0, store, nil
	}

	// Open the keychain only when at least one entry needs re-wrapping.
	kc, err := openKeychain()
	if err != nil {
		return 0, nil, fmt.Errorf("open keychain: %w", err)
	}
	privKey, _, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return 0, nil, fmt.Errorf("re-wrap requires your private key: %w", err)
	}
	defer clear(privKey[:])

	count, updated, err := rewrapStore(store, privKey, keys, ids)
	return count, updated, err
}

// rewrapNeeded reports whether any entry in store has a recipient set that
// differs from currentIDSet.
func rewrapNeeded(store *vault.Store, currentIDSet map[string]struct{}) bool {
	for _, e := range store.Entries {
		if !recipientSetsEqual(e.Recipients, currentIDSet) {
			return true
		}
	}
	return false
}

// rewrapStore re-wraps every entry whose recipient IDs differ from ids, using
// privKey to unseal the existing DEKs. Returns the count of re-wrapped entries
// and the updated store. This is a pure crypto operation with no OS side-effects.
func rewrapStore(store *vault.Store, privKey envcrypto.PrivateKey, keys []envcrypto.PublicKey, ids []string) (int, *vault.Store, error) {
	idSet := toSet(ids)

	now := time.Now().UTC()
	entries := make([]vault.Entry, len(store.Entries))
	count := 0

	for i, e := range store.Entries {
		if !recipientSetsEqual(e.Recipients, idSet) {
			newEnv, err := envcrypto.Rewrap(e.Envelope, privKey, keys)
			if err != nil {
				return 0, nil, fmt.Errorf("rewrap %s: %w", e.Name, err)
			}
			e.Envelope = newEnv
			e.Recipients = ids
			e.UpdatedAt = now
			count++
		}
		entries[i] = e
	}

	if count == 0 {
		return 0, store, nil
	}
	return count, &vault.Store{Version: store.Version, Entries: entries}, nil
}

// recipientSetsEqual reports whether entryIDs and currentSet contain exactly
// the same IDs (order-independent, no duplicates assumed).
func recipientSetsEqual(entryIDs []string, currentSet map[string]struct{}) bool {
	if len(entryIDs) != len(currentSet) {
		return false
	}
	for _, id := range entryIDs {
		if _, ok := currentSet[id]; !ok {
			return false
		}
	}
	return true
}
