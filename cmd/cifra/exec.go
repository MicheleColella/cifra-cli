package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func newExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec",
		Short: "Start an interactive shell with secrets injected",
		Long: "Opens $SHELL (or /bin/sh) with all vault env secrets injected as\n" +
			"environment variables.\n\n" +
			"Warning: env vars exported inside this shell persist for its lifetime.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := openKeychain()
			if err != nil {
				return fmt.Errorf("open keychain: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			sh := os.Getenv("SHELL")
			err = runExec(wd, sh, kc)
			var ece exitCodeError
			if errors.As(err, &ece) {
				os.Exit(ece.code)
			}
			return err
		},
	}
}

// runExec injects all vault env secrets and launches shell interactively.
// shell is used as-is; if empty it falls back to /bin/sh.
func runExec(repoRoot, shell string, kc keychain.Store) error {
	if shell == "" {
		shell = "/bin/sh"
	}
	ui.Warn("env vars exported in this shell will persist for its lifetime")
	return runRun(repoRoot, []string{shell}, kc, runFilter{})
}
