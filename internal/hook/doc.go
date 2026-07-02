// Package hook installs and manages integration hooks for Cifra:
// the Git pre-commit hook (git.go), the Claude Code PreToolUse hook (claude.go),
// and the PreToolUse request handler that blocks sensitive commands (preuse.go).
// Secret detection rules live in the sibling package internal/scan.
package hook
