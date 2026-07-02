package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <KEY>",
		Short: "Set or update a single secret in the vault (alias of add)",
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
