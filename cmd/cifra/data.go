package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newDataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Encrypt arbitrary files into the vault (text, JSON, CSV, PEM, binary)",
	}
	cmd.AddCommand(newDataStoreCmd())
	return cmd
}

func newDataStoreCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "store <file>",
		Short: "Encrypt a file into the vault for all current recipients",
		Long: "Seal an arbitrary file (confidential data, internal config, certificates)\n" +
			"client-side for all current recipients into .cifra/secrets.enc. The file\n" +
			"is read only on this machine; only ciphertext is stored, never plaintext.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runDataStore(wd, args[0], name)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name to store the file under (defaults to the file's base name)")
	return cmd
}

// runDataStore is the testable core of "cifra data store <file>".
func runDataStore(repoRoot, filePath, name string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	keys, ids, err := loadRecipientKeys(repoRoot)
	if err != nil {
		return err
	}

	payload, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	if name == "" {
		name = filepath.Base(filePath)
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	entry, err := sealEntry(name, vault.KindFile, payload, keys, ids)
	if err != nil {
		return fmt.Errorf("seal %s: %w", name, err)
	}
	store = store.Upsert(entry)

	if err := vault.SaveStore(repoRoot, store); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("Sealed %s (%d bytes) into %s/secrets.enc", name, len(payload), vault.DirName))
	ui.Info(fmt.Sprintf("  algorithm   %s", entry.Algorithm))
	ui.Info(fmt.Sprintf("  recipients  %d (%s)", len(ids), strings.Join(ids, ", ")))
	ui.Info("plaintext never leaves this machine — only ciphertext is stored")
	return nil
}
