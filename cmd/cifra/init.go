package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newInitCmd() *cobra.Command {
	var force, upgrade bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new Cifra vault in the current repository",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if upgrade {
				return runInitUpgrade(wd)
			}
			return runInit(wd, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "reinitialize an existing vault")
	cmd.Flags().BoolVar(&upgrade, "upgrade", false,
		"register the git merge driver on an existing vault (for repos cloned before it existed)")
	return cmd
}

func runInit(repoRoot string, force bool) error {
	remote, err := git.DetectOrigin(repoRoot)
	if err != nil {
		ui.Warn("could not detect git remote: " + err.Error())
	}

	cfg, err := vault.Init(repoRoot, remote, force)
	if err != nil {
		if errors.Is(err, vault.ErrAlreadyInitialized) {
			// If .cifra/ was committed by a remote (e.g., the user cloned a repo
			// that already had the vault), treat init as a no-op rather than an error.
			// Locally created but never-pushed vault files remain an error (see
			// TestRunInit_AlreadyInitialized) so --force is still required there.
			if git.IsVaultTracked(repoRoot) {
				ui.Info(fmt.Sprintf("Vault already initialized at %s/", vault.DirName))
				// Still ensure the merge driver is registered locally — .git/config
				// does not travel with a clone, so a cloned vault needs it added.
				registerMergeDriver(repoRoot)
				return nil
			}
			return err
		}
		return fmt.Errorf("init vault: %w", err)
	}

	ui.OK(fmt.Sprintf("Vault initialized at %s/", vault.DirName))
	ui.Info(fmt.Sprintf("backend  %s", cfg.Backend))
	if cfg.Remote != "" {
		ui.Info(fmt.Sprintf("remote   %s", cfg.Remote))
	} else {
		ui.Info("remote   (none detected — run inside a git repository with an origin remote)")
	}
	ui.Info("No third-party server — your remote is the only backend.")
	registerMergeDriver(repoRoot)
	return nil
}

// runInitUpgrade registers the git merge driver on an already-initialized vault,
// for repos cloned before the driver existed (or before this machine ran init).
// It does not re-create vault files.
func runInitUpgrade(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("no vault to upgrade — run `cifra init` first")
	}
	registerMergeDriver(repoRoot)
	ui.OK("Vault upgraded — git merge driver registered")
	return nil
}

// registerMergeDriver wires the ciphertext-only merge driver into git: the local
// .git/config definition and the committed .gitattributes route. Failures are
// warned, not fatal — the vault still works, and `cifra pull` refuses loudly (via
// git.MergeDriverMisconfigured) if the config half is missing.
func registerMergeDriver(repoRoot string) {
	if err := git.RegisterMergeDriver(repoRoot); err != nil {
		ui.Warn("could not register git merge driver in .git/config: " + err.Error())
		return
	}
	added, err := git.EnsureGitAttributes(repoRoot)
	if err != nil {
		ui.Warn("could not update .gitattributes: " + err.Error())
		return
	}
	if added {
		ui.Info("git merge driver registered (.gitattributes + .git/config) — commit .gitattributes to share it")
	}
}
