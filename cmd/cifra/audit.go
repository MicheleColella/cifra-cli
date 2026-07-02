package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/audit"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the AI interaction audit log",
	}
	cmd.AddCommand(newAuditLogCmd())
	return cmd
}

func newAuditLogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show or verify the AI audit log",
	}
	cmd.AddCommand(newAuditLogShowCmd(), newAuditLogVerifyCmd())
	return cmd
}

func newAuditLogShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print recent audit log entries",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runAuditLogShow(wd)
		},
	}
}

func newAuditLogVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the integrity of the audit log hash chain",
		RunE: func(_ *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runAuditLogVerify(wd)
		},
	}
}

func runAuditLogShow(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	entries, err := audit.LoadEntries(repoRoot)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		ui.Info("No audit log entries yet.")
		return nil
	}
	for _, e := range entries {
		line := fmt.Sprintf("%s  %-12s  %-14s  %s", e.Time, e.Tool, e.Action, e.Target)
		if e.Pattern != "" {
			line += fmt.Sprintf("  (pattern: %s)", e.Pattern)
		}
		ui.Info(line)
	}
	return nil
}

func runAuditLogVerify(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	entries, err := audit.LoadEntries(repoRoot)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		ui.Info("Audit log is empty — nothing to verify.")
		return nil
	}
	if err := audit.VerifyChain(entries); err != nil {
		ui.Fail(fmt.Sprintf("Audit log integrity check FAILED: %v", err))
		return err
	}
	ui.OK(fmt.Sprintf("Audit log OK — %d entries, hash chain intact", len(entries)))
	return nil
}
