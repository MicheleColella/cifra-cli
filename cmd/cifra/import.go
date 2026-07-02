package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import secrets from a .env file into the vault",
		Long: "Parse a dotenv file and seal every secret client-side for all current\n" +
			"recipients into .cifra/secrets.enc. The plaintext is read only on this\n" +
			"machine and never written back to disk — only ciphertext is stored.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runImport(wd, args[0])
		},
	}
}

// runImport is the testable core of "cifra import <file>".
func runImport(repoRoot, dotenvPath string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	keys, ids, err := loadRecipientKeys(repoRoot)
	if err != nil {
		return err
	}

	f, err := os.Open(dotenvPath)
	if err != nil {
		return fmt.Errorf("open dotenv file: %w", err)
	}
	defer func() { _ = f.Close() }()

	vars, err := vault.ParseDotenv(f)
	if err != nil {
		return err
	}
	if len(vars) == 0 {
		ui.Info("no secrets found in " + dotenvPath)
		return nil
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	ui.Header(fmt.Sprintf("Encrypting %d secret(s) for %d recipient(s)", len(vars), len(ids)))
	for _, v := range vars {
		entry, err := sealEntry(v.Key, vault.KindEnv, []byte(v.Value), keys, ids)
		if err != nil {
			return fmt.Errorf("seal %s: %w", v.Key, err)
		}
		store = store.Upsert(entry)
		ui.Info(fmt.Sprintf("  %-30s %s", v.Key, entry.Algorithm))
	}

	if err := vault.SaveStore(repoRoot, store); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("Sealed %d secret(s) into %s/secrets.enc", len(vars), vault.DirName))
	ui.Info("plaintext never leaves this machine — only ciphertext is stored")
	return nil
}
