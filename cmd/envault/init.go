package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/envault-cli/internal/git"
	"github.com/MicheleColella/envault-cli/internal/ui"
	"github.com/MicheleColella/envault-cli/internal/vault"
)

func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new Envault vault in the current repository",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runInit(wd, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "reinitialize an existing vault")
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
	return nil
}
