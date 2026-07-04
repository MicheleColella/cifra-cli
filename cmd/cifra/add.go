package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <KEY>",
		Short: "Add or update a single secret in the vault",
		Long: "Seal a single secret for all current recipients.\n" +
			"Reads the value from stdin (piped) or prompts interactively without echo.\n" +
			"The plaintext never leaves this machine — only ciphertext is stored.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			if err := blockSealInAgentMode(force); err != nil {
				return err
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			value, err := readSecretValue(args[0])
			if err != nil {
				return err
			}
			return runAdd(wd, args[0], value)
		},
	}
	// --force overrides the in-process agent-mode guard (blockSealInAgentMode),
	// the same override the Claude Code preuse hook looks for. The guard is the
	// real boundary — it holds even when a shell wrapper (env/eval/xargs/…)
	// slips the command past the hook's best-effort parser.
	cmd.Flags().Bool("force", false, "acknowledge running this via an AI agent (agent mode otherwise blocks it)")
	return cmd
}

// blockSealInAgentMode refuses to seal a new secret when running in agent mode
// (CLAUDE_CODE=1 / --agent-safe / --json) unless --force is given. Sealing this
// way requires the plaintext to be embedded in the command, so an AI agent
// doing it exposes the value to the model exactly like a plaintext read — hence
// the same refusal cat/export already use (see runCat). This in-process guard
// is the real boundary: unlike the preuse hook, no shell wrapper (env, eval,
// xargs, brace groups, quote-splitting the binary name, …) can parse around it.
func blockSealInAgentMode(force bool) error {
	if ui.AgentMode && !force {
		return fmt.Errorf(
			"sealing a new secret is suppressed in agent mode — seal it yourself in your own terminal, or pass --force to override",
		)
	}
	return nil
}

// readSecretValue reads a secret value from stdin (piped) or prompts
// interactively with echo disabled so the value never appears on screen.
func readSecretValue(key string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return []byte(scanner.Text()), nil
	}
	fmt.Fprintf(os.Stderr, "Value for %s (hidden): ", key)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read value: %w", err)
	}
	return value, nil
}

// runAdd seals value as a KindEnv entry named name and upserts it into the vault.
func runAdd(repoRoot, name string, value []byte) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	keys, ids, err := loadRecipientKeys(repoRoot)
	if err != nil {
		return err
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	entry, err := sealEntry(name, vault.KindEnv, value, keys, ids)
	if err != nil {
		return fmt.Errorf("seal %s: %w", name, err)
	}

	store = store.Upsert(entry)
	if err := vault.SaveStore(repoRoot, store); err != nil {
		return err
	}

	ui.OK(fmt.Sprintf("sealed %s for %d recipient(s)", name, len(ids)))
	ui.Info("plaintext never leaves this machine — only ciphertext is stored")
	return nil
}
