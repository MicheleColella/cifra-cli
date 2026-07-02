package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage the key-unlock agent (ssh-agent-style, for headless cifra callers)",
		Long: "Caches your decrypted private key in memory for a bounded time so headless\n" +
			"callers — most importantly the Claude Code MCP server, which has no TTY to\n" +
			"prompt for a passphrase — can use it without CIFRA_PASSPHRASE.\n\n" +
			"Unlock once from a real terminal; the agent runs detached and keeps serving\n" +
			"requests (including from sessions started after this terminal closes) until\n" +
			"the TTL expires or you lock/stop it.",
	}
	cmd.AddCommand(
		newAgentUnlockCmd(),
		newAgentLockCmd(),
		newAgentStopCmd(),
		newAgentStatusCmd(),
		newAgentServeInternalCmd(),
	)
	return cmd
}

func newAgentUnlockCmd() *cobra.Command {
	var ttl time.Duration

	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock your identity's private key into the agent for ttl",
		Long: "Finds your recipient identity the same way `cifra run` does (scans this\n" +
			"vault's recipients against the OS keychain), prompts once for its passphrase,\n" +
			"and hands the decrypted key to the agent — starting it detached if it isn't\n" +
			"already running. Must be run from a real terminal (no TTY, no unlock).",
		RunE: func(_ *cobra.Command, _ []string) error {
			kc, err := openKeychain()
			if err != nil {
				return fmt.Errorf("open keychain: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runAgentUnlock(wd, kc, ttl)
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", agent.DefaultTTL, "how long the key stays unlocked")
	return cmd
}

func runAgentUnlock(repoRoot string, kc keychain.Store, ttl time.Duration) error {

	priv, id, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return err
	}
	defer clear(priv[:])

	if err := agent.Unlock(id, priv[:], ttl); err != nil {
		return fmt.Errorf("unlock agent: %w", err)
	}

	ui.OK(fmt.Sprintf("Unlocked %s in the agent for %s", id, ttl))
	ui.Info("Claude Code (and any other headless cifra caller) can now use it without a passphrase prompt")
	return nil
}

func newAgentLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Clear every key cached in the agent (no-op if no agent is running)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := agent.Lock(); err != nil {
				return err
			}
			ui.OK("Agent locked — all cached keys cleared")
			return nil
		},
	}
}

func newAgentStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Clear all cached keys and terminate the agent process (no-op if not running)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := agent.Stop(); err != nil {
				return err
			}
			ui.OK("Agent stopped")
			return nil
		},
	}
}

type agentStatusEntry struct {
	ID               string `json:"id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

func newAgentStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show which identities are currently unlocked in the agent",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAgentStatus()
		},
	}
}

func runAgentStatus() error {
	entries, err := agent.Status()
	if err != nil {
		return err
	}

	if ui.AgentMode {
		out := make([]agentStatusEntry, len(entries))
		for i, e := range entries {
			out[i] = agentStatusEntry{ID: e.ID, ExpiresInSeconds: e.ExpiresInSeconds}
		}
		ui.JSONResult(out)
		return nil
	}

	if len(entries) == 0 {
		ui.Info("No agent running, or no keys unlocked. Use `cifra agent unlock` to start one.")
		return nil
	}

	ui.Header("Cifra Agent — unlocked identities")
	for _, e := range entries {
		ui.Info(fmt.Sprintf("  %-30s  expires in %s", e.ID, time.Duration(e.ExpiresInSeconds)*time.Second))
	}
	return nil
}

// newAgentServeInternalCmd is the actual server loop entry point. Invoked
// only by agent.EnsureRunning's auto-spawn path — never by a user directly.
func newAgentServeInternalCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "serve-internal",
		Short:         "Run the agent server loop (internal)",
		Hidden:        true,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(_ *cobra.Command, _ []string) error {
			ln, err := agent.Listen()
			if err != nil {
				return err
			}
			agent.Serve(ln)
			return nil
		},
	}
}
