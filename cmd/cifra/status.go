package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/hook"
	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

type statusResult struct {
	Initialized           bool `json:"initialized"`
	Recipients            int  `json:"recipients"`
	Secrets               int  `json:"secrets"`
	GitHook               bool `json:"git_hook"`
	PrivacyShieldPatterns int  `json:"privacy_shield_patterns"`
	AgentUnlockedKeys     int  `json:"agent_unlocked_keys"`
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check vault initialization, recipients, secrets, and integrations",
		Long: `Displays the health and integration status of the vault.

Shows:
  • Vault initialized — whether .cifra/ is set up in this repo
  • Recipients — number of team members who can decrypt secrets
  • Secrets — number of sealed env vars and files
  • Git hook — whether the pre-commit scanner is installed
  • Privacy Shield patterns — number of protected paths blocking AI access
  • Agent unlocked keys — number of identities cached by the key-unlock daemon

Use this to verify the vault is ready, debug integration issues, or confirm
AI Privacy Shield is active. Output is JSON in agent mode (--agent-safe).`,
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runStatus(wd)
		},
	}
}

// computeStatus builds a statusResult from the vault, git hook, and Privacy
// Shield state. Read-only, no output — shared by runStatus and the MCP
// cifra_status tool.
func computeStatus(repoRoot string) statusResult {
	res := statusResult{
		Initialized: vault.IsInitialized(repoRoot),
		GitHook:     hook.IsGitHookInstalled(repoRoot),
	}

	if res.Initialized {
		if recipients, err := vault.ListRecipients(repoRoot); err == nil {
			res.Recipients = len(recipients)
		}
		if store, err := vault.LoadStore(repoRoot); err == nil {
			res.Secrets = len(store.Entries)
		}
		if patterns, err := protect.LoadPatterns(repoRoot); err == nil {
			res.PrivacyShieldPatterns = len(patterns)
		}
	}
	if entries, err := agent.Status(); err == nil {
		res.AgentUnlockedKeys = len(entries)
	}
	return res
}

// runStatus collects and displays vault health (human or JSON based on AgentMode).
func runStatus(repoRoot string) error {
	res := computeStatus(repoRoot)

	if ui.AgentMode {
		ui.JSONResult(res)
		return nil
	}

	check := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}

	ui.Header("Cifra Status")
	ui.Info(fmt.Sprintf("  Vault initialized        %s", check(res.Initialized)))
	ui.Info(fmt.Sprintf("  Recipients               %d", res.Recipients))
	ui.Info(fmt.Sprintf("  Secrets                  %d", res.Secrets))
	ui.Info(fmt.Sprintf("  Git hook                 %s", check(res.GitHook)))
	ui.Info(fmt.Sprintf("  Privacy Shield patterns  %d", res.PrivacyShieldPatterns))
	ui.Info(fmt.Sprintf("  Agent unlocked keys      %d", res.AgentUnlockedKeys))
	return nil
}
