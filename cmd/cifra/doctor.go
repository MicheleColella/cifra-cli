package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/hook"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

type doctorResult struct {
	Binary          string `json:"binary"`
	KeychainBackend bool   `json:"keychain_backend"`
	GitRemote       string `json:"git_remote"` // credentials redacted
	Initialized     bool   `json:"initialized"`
	Recipients      int    `json:"recipients"`
	Secrets         int    `json:"secrets"`
	GitHook         bool   `json:"git_hook"`
	PrivacyShield   int    `json:"privacy_shield_patterns"`
	AgentRunning    bool   `json:"agent_running"`
	AgentUnlocked   int    `json:"agent_unlocked_keys"`
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose install state, hooks, keychain, and Git remote (no secrets exposed)",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runDoctor(wd)
		},
	}
}

func runDoctor(repoRoot string) error {
	bin, _ := os.Executable()
	_, kcErr := keychain.New()
	remote, _ := git.DetectOrigin(repoRoot)

	res := doctorResult{
		Binary:          bin,
		KeychainBackend: kcErr == nil,
		GitRemote:       redactRemote(remote),
		Initialized:     vault.IsInitialized(repoRoot),
		GitHook:         hook.IsGitHookInstalled(repoRoot),
	}
	if res.Initialized {
		if r, err := vault.ListRecipients(repoRoot); err == nil {
			res.Recipients = len(r)
		}
		if s, err := vault.LoadStore(repoRoot); err == nil {
			res.Secrets = len(s.Entries)
		}
		if p, err := protect.LoadPatterns(repoRoot); err == nil {
			res.PrivacyShield = len(p)
		}
	}
	res.AgentRunning = agent.IsRunning()
	if entries, err := agent.Status(); err == nil {
		res.AgentUnlocked = len(entries)
	}

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
	remoteStr := res.GitRemote
	if remoteStr == "" {
		remoteStr = "(none)"
	}

	ui.Header("Cifra Doctor")
	ui.Info(fmt.Sprintf("  Binary                   %s", res.Binary))
	ui.Info(fmt.Sprintf("  Keychain backend         %s", check(res.KeychainBackend)))
	ui.Info(fmt.Sprintf("  Git remote               %s", remoteStr))
	ui.Info(fmt.Sprintf("  Vault initialized        %s", check(res.Initialized)))
	ui.Info(fmt.Sprintf("  Recipients               %d", res.Recipients))
	ui.Info(fmt.Sprintf("  Secrets                  %d", res.Secrets))
	ui.Info(fmt.Sprintf("  Git hook                 %s", check(res.GitHook)))
	ui.Info(fmt.Sprintf("  Privacy Shield patterns  %d", res.PrivacyShield))
	ui.Info(fmt.Sprintf("  Key-unlock agent         %s (%d key(s) unlocked)", check(res.AgentRunning), res.AgentUnlocked))
	ui.Info("  Claude Code              install the Cifra plugin (" + pluginInstallHint + ")")
	return nil
}

// redactRemote strips any userinfo (user:token@) from an scheme://… remote URL
// so a credential embedded in the origin URL is never printed by doctor.
// scp-like syntax (git@host:path) carries no secret and is left untouched.
func redactRemote(remote string) string {
	i := strings.Index(remote, "://")
	if i < 0 {
		return remote
	}
	rest := remote[i+3:]
	at := strings.Index(rest, "@")
	slash := strings.Index(rest, "/")
	if at < 0 || (slash >= 0 && at > slash) {
		return remote // no userinfo before the path
	}
	return remote[:i+3] + "***@" + rest[at+1:]
}
