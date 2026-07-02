package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newProtectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Manage protected paths and encrypt sensitive files",
	}
	cmd.AddCommand(
		newProtectAddCmd(),
		newProtectListCmd(),
		newProtectRemoveCmd(),
		newProtectEncryptCmd(),
	)
	return cmd
}

func newProtectAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <path|pattern>",
		Short: "Register a path or glob as protected (AI cannot read it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runProtectAdd(wd, args[0])
		},
	}
}

func newProtectListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered protected paths",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runProtectList(wd)
		},
	}
}

func newProtectRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <path|pattern>",
		Short: "Unregister a protected path",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runProtectRemove(wd, args[0])
		},
	}
}

func newProtectEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file into the vault and remove the plaintext from disk",
		Long: "Seals the file as a KindFile vault entry so the plaintext no longer exists\n" +
			"on disk. The ciphertext is stored in .cifra/secrets.enc alongside env secrets.\n\n" +
			"The file is accessible at runtime via CIFRA_FILE_<NAME>=<content> when using\n" +
			"`cifra run`. The original file is deleted after successful encryption.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			kc, err := openKeychain()
			if err != nil {
				return fmt.Errorf("open keychain: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runProtectEncrypt(wd, args[0], kc)
		},
	}
}

func runProtectAdd(repoRoot, pattern string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	if err := protect.AddPattern(repoRoot, pattern); err != nil {
		return err
	}
	ui.OK(fmt.Sprintf("Protected: %s", pattern))
	ui.Info("Claude Code hook will block Read/Write/Edit and Bash access to matching paths")
	return nil
}

func runProtectList(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	patterns, err := protect.LoadPatterns(repoRoot)
	if err != nil {
		return err
	}
	if len(patterns) == 0 {
		ui.Info("No protected paths registered. Use `cifra protect add <path>` to register one.")
		return nil
	}
	for _, p := range patterns {
		ui.Info(p)
	}
	return nil
}

func runProtectRemove(repoRoot, pattern string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	if err := protect.RemovePattern(repoRoot, pattern); err != nil {
		return err
	}
	ui.OK(fmt.Sprintf("Unprotected: %s", pattern))
	return nil
}

func runProtectEncrypt(repoRoot, filePath string, kc keychain.Store) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	payload, err := os.ReadFile(filePath) //nolint:gosec // filePath is user-supplied intentionally
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	keys, ids, err := loadRecipientKeys(repoRoot)
	if err != nil {
		return err
	}

	name := filePath // use path as the entry name
	entry, err := sealEntry(name, vault.KindFile, payload, keys, ids)
	if err != nil {
		return fmt.Errorf("seal file: %w", err)
	}
	clear(payload)

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}
	newStore := store.Upsert(entry)
	if err := vault.SaveStore(repoRoot, newStore); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	// Verify we can re-seal before deleting the original.
	privKey, _, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return fmt.Errorf("verify encryption (cannot read back — original kept): %w", err)
	}
	if _, verifyErr := envcrypto.Unseal(entry.Envelope, privKey); verifyErr != nil {
		return fmt.Errorf("verify decryption failed — original kept: %w", verifyErr)
	}
	clear(privKey[:])

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("remove plaintext (vault entry saved): %w", err)
	}

	ui.OK(fmt.Sprintf("Encrypted %s → vault (.cifra/secrets.enc)", filePath))
	ui.Info("Plaintext removed from disk. Access via `cifra run` (injects as CIFRA_FILE_<NAME>)")
	return nil
}
