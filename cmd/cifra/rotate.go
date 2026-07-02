package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <KEY>",
		Short: "Re-seal a secret with a fresh data key for all current recipients",
		Long: "Generates a new data encryption key and re-encrypts the secret from scratch.\n" +
			"Use after removing a recipient for true revocation — re-wrapping alone does\n" +
			"not invalidate ciphertext that the removed recipient already downloaded.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := openKeychain()
			if err != nil {
				return fmt.Errorf("open keychain: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runRotate(wd, args[0], kc)
		},
	}
}

func runRotate(repoRoot, name string, kc keychain.Store) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	var (
		found   vault.Entry
		foundOK bool
	)
	for _, e := range store.Entries {
		if e.Name != name {
			continue
		}
		if e.Kind != vault.KindEnv {
			return fmt.Errorf("%q is a file entry — only env secrets can be rotated via this command", name)
		}
		found, foundOK = e, true
		break
	}
	if !foundOK {
		return fmt.Errorf("secret %q not found in vault", name)
	}

	priv, _, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return err
	}
	defer clear(priv[:])

	plaintext, err := envcrypto.Unseal(found.Envelope, priv)
	if err != nil {
		return fmt.Errorf("decrypt %s: %w", name, err)
	}
	defer clear(plaintext)

	keys, ids, err := loadRecipientKeys(repoRoot)
	if err != nil {
		return err
	}

	entry, err := sealEntry(name, vault.KindEnv, plaintext, keys, ids)
	if err != nil {
		return fmt.Errorf("rotate %s: %w", name, err)
	}

	store = store.Upsert(entry)
	if err := vault.SaveStore(repoRoot, store); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("rotated %s — new data key sealed for %d recipient(s)", name, len(ids)))
	ui.Info("removed recipients can no longer decrypt the new ciphertext")
	return nil
}
