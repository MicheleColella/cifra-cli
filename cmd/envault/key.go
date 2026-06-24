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
			kc, err := keychain.New()
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
			kc, err := keychain.New()
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

// ---------- helpers ----------

func pubKeyFingerprint(pub envcrypto.PublicKey) string {
	h := sha256.Sum256(pub[:])
	return "sha256:" + hex.EncodeToString(h[:])
}
