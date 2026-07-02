package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/envault-cli/internal/crypto"
	"github.com/MicheleColella/envault-cli/internal/keychain"
	"github.com/MicheleColella/envault-cli/internal/secmem"
	"github.com/MicheleColella/envault-cli/internal/ui"
	"github.com/MicheleColella/envault-cli/internal/vault"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage X25519 identity keys and vault recipients",
	}
	cmd.AddCommand(
		newKeyNewCmd(),
		newKeyListCmd(),
		newKeyExportCmd(),
		newKeyImportCmd(),
		newKeyDeleteCmd(),
		newKeyResealCmd(),
	)
	return cmd
}

// ---------- key new ----------

func newKeyNewCmd() *cobra.Command {
	var id string

	cmd := &cobra.Command{
		Use:   "new",
		Short: "Generate a new X25519 keypair and seal the private key in the OS keychain",
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, err := openKeychain()
			if err != nil {
				return err
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runKeyNew(id, kc, wd)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "identity for this keypair, e.g. alice@example.com")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// runKeyNew is the testable core of "envault key new".
func runKeyNew(id string, kc keychain.Store, repoRoot string) error {
	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	defer clear(priv[:])

	if err := kc.Seal(id, priv[:]); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("Key generated for %s", id))
	ui.Info(fmt.Sprintf("fingerprint  %s", pubKeyFingerprint(pub)))
	ui.Info("cipher       X25519 → AES-256-GCM")
	ui.Info("private key  sealed in OS keychain (never written to disk)")

	if vault.IsInitialized(repoRoot) {
		r := vault.Recipient{ID: id, PublicKey: pub}
		if err := vault.AddRecipient(repoRoot, r); err != nil {
			if errors.Is(err, vault.ErrRecipientAlreadyExists) {
				ui.Info("recipient    already in .envault/recipients — skipped")
			} else {
				ui.Warn("could not add to .envault/recipients: " + err.Error())
			}
		} else {
			ui.Info("recipient    added to .envault/recipients")
		}
	}
	return nil
}

// ---------- key list ----------

func newKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all recipients in .envault/recipients",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runKeyList(wd)
		},
	}
}

// runKeyList is the testable core of "envault key list".
func runKeyList(repoRoot string) error {
	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return err
	}

	if len(recipients) == 0 {
		ui.Info("no recipients found in .envault/recipients")
		return nil
	}

	ui.Header(fmt.Sprintf("%d recipient(s) in .envault/recipients", len(recipients)))
	for _, r := range recipients {
		pub := envcrypto.PublicKey(r.PublicKey)
		ui.Info(fmt.Sprintf("  %-40s  %s", r.ID, pubKeyFingerprint(pub)))
	}
	return nil
}

// ---------- key export ----------

func newKeyExportCmd() *cobra.Command {
	var id string
	var public bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export your public key so teammates can add you as a recipient",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !public {
				return fmt.Errorf("specify --public to export the public key")
			}
			kc, err := openKeychain()
			if err != nil {
				return err
			}
			return runKeyExport(id, kc)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "identity of the keypair to export, e.g. alice@example.com")
	cmd.Flags().BoolVar(&public, "public", false, "export the public key (required)")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// runKeyExport is the testable core of "envault key export --public".
func runKeyExport(id string, kc keychain.Store) error {
	privBytes, err := kc.Unseal(id)
	if err != nil {
		return fmt.Errorf("unseal key for %s: %w", id, err)
	}
	secmem.Lock(privBytes)
	defer secmem.Unlock(privBytes)
	defer clear(privBytes) // zero the heap allocation returned by kc.Unseal

	var priv envcrypto.PrivateKey
	copy(priv[:], privBytes)
	defer clear(priv[:])

	pub, err := envcrypto.DerivePublicKey(priv)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	line := fmt.Sprintf("%s %s", id, hex.EncodeToString(pub[:]))
	_, _ = fmt.Fprintln(ui.Out, line)
	return nil
}

// ---------- key import ----------

func newKeyImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <id> <hex-pubkey>",
		Short: "Add a teammate's public key to .envault/recipients",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runKeyImport(wd, args[0], args[1])
		},
	}
}

// runKeyImport is the testable core of "envault key import <id> <hex-pubkey>".
func runKeyImport(repoRoot, id, hexPubKey string) error {
	r, err := vault.ParseRecipientLine(id + " " + hexPubKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if err := envcrypto.ValidatePublicKey(envcrypto.PublicKey(r.PublicKey)); err != nil {
		return fmt.Errorf("refusing to add %s: %w", id, err)
	}

	if err := vault.AddRecipient(repoRoot, r); err != nil {
		if errors.Is(err, vault.ErrRecipientAlreadyExists) {
			ui.Info(fmt.Sprintf("%s is already a recipient — skipped", id))
			return nil
		}
		return err
	}

	pub := envcrypto.PublicKey(r.PublicKey)
	ui.OK(fmt.Sprintf("Added recipient %s", id))
	ui.Info(fmt.Sprintf("fingerprint  %s", pubKeyFingerprint(pub)))
	return nil
}

// ---------- key delete ----------

func newKeyDeleteCmd() *cobra.Command {
	var id string
	var keepRecipient bool

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove a keypair from the OS keychain (and from .envault/recipients)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, err := openKeychain()
			if err != nil {
				return err
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runKeyDelete(id, kc, wd, keepRecipient)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "identity of the keypair to delete, e.g. alice@example.com")
	cmd.Flags().BoolVar(&keepRecipient, "keep-recipient", false, "do not remove the entry from .envault/recipients")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// runKeyDelete is the testable core of "envault key delete".
func runKeyDelete(id string, kc keychain.Store, repoRoot string, keepRecipient bool) error {
	if err := kc.Delete(id); err != nil {
		return err
	}
	ui.OK(fmt.Sprintf("Key deleted from keychain for %s", id))

	if keepRecipient || !vault.IsInitialized(repoRoot) {
		return nil
	}

	if err := vault.RemoveRecipient(repoRoot, id); err != nil {
		if errors.Is(err, vault.ErrRecipientNotFound) {
			return nil // not in recipients — nothing to do
		}
		ui.Warn("could not remove from .envault/recipients: " + err.Error())
		return nil
	}
	ui.Info("removed from .envault/recipients")
	return nil
}

// ---------- key reseal ----------

func newKeyResealCmd() *cobra.Command {
	var id string

	cmd := &cobra.Command{
		Use:   "reseal",
		Short: "Migrate a legacy unencrypted keychain key to the encrypted-at-rest format",
		Long: "Re-encrypts the private key for --id under a passphrase-derived key " +
			"(Argon2id -> AES-256-GCM). Use this to close the residual left by a key " +
			"generated before this protection existed, or to change its passphrase. " +
			"Safe to run on a key that is already protected — it will simply be resealed.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := openRawKeychain()
			if err != nil {
				return err
			}
			return runKeyReseal(id, raw)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "identity of the keypair to reseal, e.g. alice@example.com")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// runKeyReseal is the testable core of "envault key reseal".
func runKeyReseal(id string, raw keychain.Store) error {
	if err := keychain.Reseal(raw, askPassphrase, id); err != nil {
		return fmt.Errorf("reseal key for %s: %w", id, err)
	}
	ui.OK(fmt.Sprintf("Key resealed for %s", id))
	ui.Info("private key is now encrypted at rest under the passphrase you just set")
	return nil
}

// ---------- helpers ----------

func pubKeyFingerprint(pub envcrypto.PublicKey) string {
	h := sha256.Sum256(pub[:])
	return "sha256:" + hex.EncodeToString(h[:])
}
