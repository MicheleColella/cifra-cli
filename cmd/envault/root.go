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
