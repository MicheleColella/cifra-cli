package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/hook"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newUninstallCmd() *cobra.Command {
	var removeKeys bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove everything Cifra added: the .cifra/ vault and the Git hook (--keys also clears keychain)",
		Long: "Reverses init and every integration Cifra installed, leaving the host as before.\n\n" +
			"Removes: the .cifra/ vault directory and the Git pre-commit hook.\n" +
			"  --keys    also delete this machine's vault keys from the OS keychain (IRREVERSIBLE)\n\n" +
			"Claude Code integration is a plugin — remove it with '/plugin uninstall cifra'.\n\n" +
			"Idempotent and safe to run repeatedly. Does not delete the cifra binary —\n" +
			"run scripts/install.sh --uninstall (or rm the binary) for that.",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runUninstall(wd, removeKeys)
		},
	}
	cmd.Flags().BoolVar(&removeKeys, "keys", false, "also delete this machine's vault keys from the keychain (irreversible)")
	return cmd
}

// runUninstall removes every Cifra integration. Each step is guarded so the
// command is idempotent: re-running it on an already-clean host is a no-op.
func runUninstall(repoRoot string, removeKeys bool) error {
	var removed []string

	if hook.IsGitHookInstalled(repoRoot) {
		if err := hook.UninstallGitHook(repoRoot); err != nil {
			return fmt.Errorf("remove git hook: %w", err)
		}
		removed = append(removed, "Git pre-commit hook")
	}

	// Keys must be cleared before the vault dir is removed: removeVaultKeys
	// reads the recipient list from .cifra/recipients.
	if removeKeys {
		n, err := removeVaultKeys(repoRoot)
		if err != nil {
			ui.Warn("could not clear keychain: " + err.Error())
		} else if n > 0 {
			removed = append(removed, fmt.Sprintf("%d keychain key(s)", n))
		}
	}

	// Remove the local vault directory, undoing `cifra init`.
	// ponytail: working-tree only — if .cifra/ was committed, git still has it
	// (shows as a deletion); recover with `git checkout .cifra`.
	vaultDir := filepath.Join(repoRoot, vault.DirName)
	if _, err := os.Stat(vaultDir); err == nil {
		if err := os.RemoveAll(vaultDir); err != nil {
			return fmt.Errorf("remove %s: %w", vault.DirName, err)
		}
		removed = append(removed, vault.DirName+"/ directory")
	}

	if len(removed) == 0 {
		ui.OK("Nothing to remove — host is already clean")
		return nil
	}
	for _, r := range removed {
		ui.Info("removed " + r)
	}
	ui.OK("Cifra removed from this repo")
	ui.Info("Binary not deleted — run scripts/install.sh --uninstall or rm it manually")
	return nil
}

// removeVaultKeys deletes from the OS keychain any vault recipient key that is
// present on this machine. Uses the raw keychain (no passphrase needed to
// delete) and ignores ErrNotFound for recipients whose keys live elsewhere.
func removeVaultKeys(repoRoot string) (int, error) {
	if !vault.IsInitialized(repoRoot) {
		return 0, nil
	}
	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return 0, err
	}
	kc, err := keychain.New()
	if err != nil {
		return 0, err
	}
	var n int
	for _, r := range recipients {
		if err := kc.Delete(r.ID); err == nil {
			n++
		} else if !errors.Is(err, keychain.ErrNotFound) {
			return n, err
		}
	}
	return n, nil
}
