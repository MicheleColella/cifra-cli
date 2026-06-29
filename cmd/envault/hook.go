package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/envault-cli/internal/hook"
	"github.com/MicheleColella/envault-cli/internal/ui"
)

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Install or remove Git and editor hooks",
	}
	cmd.AddCommand(newHookInstallCmd())
	return cmd
}

func newHookInstallCmd() *cobra.Command {
	var gitHook bool
	var uninstall bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install integration hooks",
		Long: "Install hooks that integrate Envault into your development workflow.\n\n" +
			"  envault hook install --git             install the Git pre-commit hook\n" +
			"  envault hook install --git --uninstall remove the Git pre-commit hook",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !gitHook {
				return fmt.Errorf("specify --git to target the Git pre-commit hook")
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if uninstall {
				return runHookUninstallGit(wd)
			}
			return runHookInstallGit(wd)
		},
	}

	cmd.Flags().BoolVar(&gitHook, "git", false, "target the Git pre-commit hook")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the hook instead of installing it")
	return cmd
}

func runHookInstallGit(repoRoot string) error {
	alreadyInstalled := hook.IsGitHookInstalled(repoRoot)

	if err := hook.InstallGitHook(repoRoot); err != nil {
		return err
	}

	if alreadyInstalled {
		ui.Info("Git pre-commit hook already installed")
		return nil
	}

	ui.OK("Git pre-commit hook installed (.git/hooks/pre-commit)")
	ui.Info("Scans staged diff via envault scan (12+ patterns, entropy detection, .envaultignore)")
	ui.Info("Remove with: envault hook install --git --uninstall")
	return nil
}

func runHookUninstallGit(repoRoot string) error {
	if err := hook.UninstallGitHook(repoRoot); err != nil {
		return err
	}
	ui.OK("Git pre-commit hook removed")
	return nil
}
