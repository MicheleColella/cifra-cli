package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/hook"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Install or remove the Git pre-commit hook",
	}
	cmd.AddCommand(newHookInstallCmd())
	cmd.AddCommand(newHookPreuseCmd())
	cmd.AddCommand(newHookPostuseCmd())
	return cmd
}

func newHookInstallCmd() *cobra.Command {
	var gitHook bool
	var uninstall bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install integration hooks",
		Long: "Install hooks that integrate Cifra into your development workflow.\n\n" +
			"  cifra hook install --git              install the Git pre-commit hook\n" +
			"  cifra hook install --git --uninstall  remove the Git pre-commit hook\n\n" +
			"Claude Code integration ships as a plugin — see the README " +
			"('Claude Code plugin'), not this command.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !gitHook {
				return fmt.Errorf("specify --git to select the hook type")
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
	ui.Info("Scans staged diff via cifra scan (12+ patterns, entropy detection, .cifraignore)")
	ui.Info("Remove with: cifra hook install --git --uninstall")
	return nil
}

func runHookUninstallGit(repoRoot string) error {
	if err := hook.UninstallGitHook(repoRoot); err != nil {
		return err
	}
	ui.OK("Git pre-commit hook removed")
	return nil
}

// newHookPostuseCmd returns the hidden PostToolUse hook handler for placeholder injection.
// Invoked by the Cifra Claude Code plugin (hooks/hooks.json), not by users.
func newHookPostuseCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "postuse",
		Short:         "Claude Code PostToolUse hook handler (internal)",
		Hidden:        true,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(_ *cobra.Command, _ []string) error {
			err := hook.RunHookPostuse(os.Stdin, os.Stdout)
			if err != nil {
				os.Exit(2)
			}
			return nil
		},
	}
}

// newHookPreuseCmd returns the hidden PreToolUse hook handler invoked by the
// Cifra Claude Code plugin (hooks/hooks.json).
// Claude Code hook protocol: exit 0 = allow, exit non-zero = block.
// Stdout written before exit is displayed to Claude as the reason for blocking.
func newHookPreuseCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "preuse",
		Short:  "Claude Code PreToolUse hook handler (internal)",
		Hidden: true,
		// Suppress Cobra's default error printing — the hook writes its own
		// human-readable message to stdout for Claude to read.
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := hook.RunHookPreuse(os.Stdin, os.Stdout)
			if err != nil {
				// Non-zero exit blocks the tool call in Claude Code.
				// The block message was already written to stdout by RunHookPreuse.
				os.Exit(2)
			}
			return nil
		},
	}
}
