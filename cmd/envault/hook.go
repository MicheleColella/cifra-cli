package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/envault-cli/internal/hook"
	"github.com/MicheleColella/envault-cli/internal/ui"
)

func newHookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Install or remove Git and Claude Code hooks",
	}
	cmd.AddCommand(newHookInstallCmd())
	cmd.AddCommand(newHookPreuseCmd())
	return cmd
}

func newHookInstallCmd() *cobra.Command {
	var gitHook bool
	var claudeHook bool
	var uninstall bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install integration hooks",
		Long: "Install hooks that integrate Envault into your development workflow.\n\n" +
			"  envault hook install --git              install the Git pre-commit hook\n" +
			"  envault hook install --git --uninstall  remove the Git pre-commit hook\n" +
			"  envault hook install --claude           install the Claude Code PreToolUse hook\n" +
			"  envault hook install --claude --uninstall  remove the Claude Code hook",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !gitHook && !claudeHook {
				return fmt.Errorf("specify --git or --claude to select the hook type")
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if gitHook {
				if uninstall {
					return runHookUninstallGit(wd)
				}
				return runHookInstallGit(wd)
			}
			// --claude
			if uninstall {
				return runHookUninstallClaude(wd)
			}
			return runHookInstallClaude(wd)
		},
	}

	cmd.Flags().BoolVar(&gitHook, "git", false, "target the Git pre-commit hook")
	cmd.Flags().BoolVar(&claudeHook, "claude", false, "target the Claude Code PreToolUse hook")
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

func runHookInstallClaude(repoRoot string) error {
	alreadyInstalled := hook.IsClaudeHookInstalled(repoRoot)

	if err := hook.InstallClaudeHook(repoRoot); err != nil {
		return err
	}

	if alreadyInstalled {
		ui.Info("Claude Code hook already installed")
		return nil
	}

	ui.OK("Claude Code hook installed (.claude/settings.json)")
	ui.Info("Intercepts Bash tool calls: sets CLAUDE_CODE=1 so envault operates in agent mode")
	ui.Info("In agent mode: plaintext output is suppressed; all status is structured JSON")
	ui.Info("Remove with: envault hook install --claude --uninstall")
	ui.Info("Tip: also set ENVAULT_PASSPHRASE in your Claude Code session env for non-interactive unlock")
	return nil
}

func runHookUninstallClaude(repoRoot string) error {
	if err := hook.UninstallClaudeHook(repoRoot); err != nil {
		return err
	}
	ui.OK("Claude Code hook removed")
	return nil
}

// newHookPreuseCmd returns the hidden PreToolUse hook handler.
// It is invoked by Claude Code's PreToolUse hook (via settings.json) and reads
// the tool-call JSON from stdin. When the Bash command runs in an envault repo,
// the handler outputs an input_replace JSON that prepends CLAUDE_CODE=1 to the
// command, ensuring every envault sub-invocation operates in agent mode.
func newHookPreuseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "preuse",
		Short:  "Claude Code PreToolUse hook handler (internal)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHookPreuse(os.Stdin, os.Stdout)
		},
	}
	return cmd
}

// preuseInput is the subset of the Claude Code PreToolUse hook JSON we care about.
type preuseInput struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
}

// runHookPreuse reads Claude Code's PreToolUse JSON from r and, when in an
// envault repo, writes an input_replace response to w so Bash commands run
// with CLAUDE_CODE=1 in their environment.
func runHookPreuse(r io.Reader, w io.Writer) error {
	var input preuseInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		// Non-fatal: if we can't parse, allow the tool call unchanged.
		return nil
	}

	if input.ToolName != "Bash" {
		return nil
	}

	cmd, _ := input.ToolInput["command"].(string)
	if cmd == "" {
		return nil
	}

	// Only inject when inside an envault repo.
	wd, err := os.Getwd()
	if err != nil || !isEnvaultDir(wd) {
		return nil
	}

	if strings.HasPrefix(cmd, "CLAUDE_CODE=1 ") {
		return nil // already injected
	}

	modified := map[string]interface{}{}
	for k, v := range input.ToolInput {
		modified[k] = v
	}
	modified["command"] = "CLAUDE_CODE=1 " + cmd

	response := map[string]interface{}{
		"type": "input_replace",
		"data": modified,
	}
	b, err := json.Marshal(response)
	if err != nil {
		return nil
	}
	_, _ = fmt.Fprintln(w, string(b))
	return nil
}

// isEnvaultDir returns true when .envault/ exists under root.
func isEnvaultDir(root string) bool {
	_, err := os.Stat(root + "/.envault")
	return err == nil
}
