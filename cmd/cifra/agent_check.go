package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

type agentCheckResult struct {
	PrivacyShield bool `json:"privacy_shield"`
	OutputMasking bool `json:"output_masking"`
	Ready         bool `json:"ready"`
}

func newAgentCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "agent-check",
		Short: "Verify AI agent environment is fully configured",
		Long: "Checks that all components needed for safe AI-agent use are active:\n" +
			"  - Privacy Shield patterns (protects sensitive paths)\n" +
			"  - Output masking (CIFRA_PASSPHRASE set for PostToolUse)\n\n" +
			"The PreToolUse/PostToolUse hooks ship with the Cifra Claude Code plugin\n" +
			"(" + pluginInstallHint + ") — enablement is managed by Claude Code,\n" +
			"not detectable here.\n\n" +
			"Exits 0 when all checks pass; exits 1 otherwise.",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if err := runAgentCheck(wd); err != nil {
				if ui.AgentMode {
					// JSON result already written; skip the second ui.Fail from Execute.
					os.Exit(1)
				}
				return err
			}
			return nil
		},
	}
}

func runAgentCheck(repoRoot string) error {
	patterns, _ := protect.LoadPatterns(repoRoot)
	res := agentCheckResult{
		PrivacyShield: len(patterns) > 0,
		OutputMasking: os.Getenv("CIFRA_PASSPHRASE") != "",
	}
	// ponytail: plugin hook enablement isn't detectable from the CLI, so it's not
	// gated here — add an enabledPlugins probe only if false-readiness bites.
	res.Ready = res.PrivacyShield && res.OutputMasking

	if ui.AgentMode {
		ui.JSONResult(res)
		if !res.Ready {
			return fmt.Errorf("agent environment not fully configured")
		}
		return nil
	}

	icon := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	hint := func(ok bool, msg string) string {
		if ok {
			return ""
		}
		return "  → " + msg
	}

	ui.Header("Agent Environment Check")
	ui.Info(fmt.Sprintf("  Privacy Shield     %s%s", icon(res.PrivacyShield),
		hint(res.PrivacyShield, "run: cifra protect add <path>")))
	ui.Info(fmt.Sprintf("  Output masking     %s%s", icon(res.OutputMasking),
		hint(res.OutputMasking, "set CIFRA_PASSPHRASE in your shell or Claude Code env")))
	ui.Info("  Claude Code hook   ships with the plugin (" + pluginInstallHint + ")")

	if !res.Ready {
		return fmt.Errorf("agent environment not fully configured")
	}
	ui.OK("All checks passed — agent environment ready")
	return nil
}
