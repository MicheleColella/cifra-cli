package main

import (
	"fmt"
	"os"

	"github.com/MicheleColella/envault-cli/internal/ui"
	"github.com/spf13/cobra"
)

func Execute(ver string) {
	root := newRootCmd(ver)
	if err := root.Execute(); err != nil {
		ui.Fail(err.Error())
		os.Exit(1)
	}
}

func newRootCmd(ver string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "envault",
		Short:         "Git-backed, zero-trust secrets CLI",
		Long:          "Envault encrypts your secrets inside your team's Git repo.\nPrivate keys never leave your machine; the remote only stores ciphertext.",
		Version:       ver,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(
		newInitCmd(),
		newKeyCmd(),
		newImportCmd(),
		newAddCmd(),
		newListCmd(),
		newPushCmd(),
		newPullCmd(),
		newRunCmd(),
		newHookCmd(),
	)

	return cmd
}

func stubRun(cmd *cobra.Command, _ []string) error {
	return fmt.Errorf("%s: not implemented yet", cmd.Name())
}
