package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/envault-cli/internal/hook"
	"github.com/MicheleColella/envault-cli/internal/ui"
)

func newScanCmd() *cobra.Command {
	var (
		staged      bool
		all         bool
		minSeverity string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for secrets in staged changes or all tracked files",
		Long: "Scan for plaintext secrets using pattern matching and entropy analysis.\n\n" +
			"Patterns respect .envaultignore (gitignore-style glob patterns).\n\n" +
			"  envault scan                scan staged diff (default)\n" +
			"  envault scan --all          scan all tracked files\n" +
			"  envault scan --severity medium  also report medium-severity findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runScan(wd, staged, all, minSeverity)
		},
	}

	cmd.Flags().BoolVar(&staged, "staged", false, "scan staged diff (default if neither flag given)")
	cmd.Flags().BoolVar(&all, "all", false, "scan all tracked files")
	cmd.Flags().StringVar(&minSeverity, "severity", "high", "minimum severity to block on: critical, high, medium")
	return cmd
}

func runScan(repoRoot string, staged, all bool, minSeverityStr string) error {
	if !staged && !all {
		staged = true
	}

	minSev := hook.ParseSeverity(minSeverityStr)
	rules := hook.DefaultRules()

	ignored, err := hook.LoadIgnorePatterns(repoRoot)
	if err != nil {
		return fmt.Errorf("read .envaultignore: %w", err)
	}

	var matches []hook.Match
	if staged {
		diff, err := getStagedDiff(repoRoot)
		if err != nil {
			return err
		}
		matches = hook.ScanDiff(diff, rules, ignored)
	} else {
		matches, err = hook.ScanFiles(repoRoot, rules, ignored)
		if err != nil {
			return err
		}
	}

	blockingCount := 0
	for _, m := range matches {
		if !hook.SeverityAtLeast(m.Severity, minSev) {
			continue
		}
		loc := m.File
		if m.Line > 0 {
			loc = fmt.Sprintf("%s:%d", m.File, m.Line)
		}
		switch m.Severity {
		case hook.SeverityCritical, hook.SeverityHigh:
			ui.Fail(fmt.Sprintf("[%s] %s — %s", m.Severity, loc, m.Description))
			blockingCount++
		case hook.SeverityMedium:
			ui.Warn(fmt.Sprintf("[%s] %s — %s", m.Severity, loc, m.Description))
		}
		if m.Snippet != "" && m.Snippet != m.File {
			fmt.Fprintf(ui.Err, "  %s\n", m.Snippet)
		}
	}

	if blockingCount > 0 {
		fmt.Fprintln(ui.Err)
		fmt.Fprintln(ui.Err, "Seal secrets with: envault add <KEY>")
		fmt.Fprintln(ui.Err, "To bypass (not recommended): git commit --no-verify")
		return fmt.Errorf("%d blocking secret(s) detected", blockingCount)
	}

	return nil
}

func getStagedDiff(repoRoot string) (string, error) {
	out, err := exec.Command("git", "-C", repoRoot, "diff", "--cached", "-U0").Output() //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("git diff --cached: %w", err)
	}
	return string(out), nil
}
