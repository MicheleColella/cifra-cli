package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/envault-cli/internal/ui"
)

func Execute(ver string) {
	root := newRootCmd(ver)
	if err := root.Execute(); err != nil {
		ui.Fail(err.Error())
		os.Exit(1)
	}
}

func newRootCmd(ver string) *cobra.Command {
	var agentSafe bool

	cmd := &cobra.Command{
		Use:           "envault",
		Short:         "Git-backed, zero-trust secrets CLI",
		Long:          "Envault encrypts your secrets inside your team's Git repo.\nPrivate keys never leave your machine; the remote only stores ciphertext.",
		Version:       ver,
		SilenceErrors: true,
		SilenceUsage:  true,
		// Activate agent mode from the flag or the env var set by Claude Code.
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if agentSafe || os.Getenv("CLAUDE_CODE") == "1" {
				ui.AgentMode = true
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&agentSafe, "agent-safe", false,
		"structured JSON output for AI agent callers; suppresses plaintext secrets on stdout")

	cmd.AddCommand(
		newInitCmd(),
		newKeyCmd(),
		newImportCmd(),
		newDataCmd(),
		newAddCmd(),
		newSetCmd(),
		newRmCmd(),
		newListCmd(),
		newCatCmd(),
		newExportCmd(),
		newPushCmd(),
		newPullCmd(),
		newRotateCmd(),
		newRunCmd(),
		newExecCmd(),
		newHookCmd(),
		newScanCmd(),
	)

	return cmd
}
