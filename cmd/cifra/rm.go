package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <KEY>",
		Short: "Remove a secret from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runRm(wd, args[0])
		},
	}
}

// runRm removes the KindEnv entry named name from the vault.
func runRm(repoRoot, name string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	before := len(store.Entries)
	store = store.Delete(name, vault.KindEnv)
	if len(store.Entries) == before {
		return fmt.Errorf("secret %q not found in vault", name)
	}

	if err := vault.SaveStore(repoRoot, store); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("removed %s from vault", name))
	return nil
}
