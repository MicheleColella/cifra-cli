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
	// ponytail: --force has no effect here; it exists only as the override
	// token the Claude Code preuse hook looks for before letting an AI agent
	// run this command via Bash (see internal/hook/preuse.go).
	cmd.Flags().Bool("force", false, "acknowledge running this via an AI agent (the hook otherwise blocks it)")
	return cmd
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
