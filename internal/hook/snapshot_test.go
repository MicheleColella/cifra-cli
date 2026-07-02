package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// This file is the permanent hook-safety snapshot suite: unlike git_test.go's
// substring checks, these tests compare bytes exactly. A user's own
// pre-commit hook is their content — install/uninstall must round-trip it
// byte-for-byte, not just "contain the same words." A failure here means the
// non-destructive coexistence invariant (CLAUDE.md) has regressed.

// existingHookVariants covers the shapes of pre-commit hook a real user might
// already have when they run `envault hook install --git`.
func existingHookVariants() map[string]string {
	return map[string]string{
		"shebang_single_line":    "#!/bin/sh\necho 'existing check'\n",
		"shebang_multi_line":     "#!/bin/sh\nset -e\necho one\necho two\nexit 0\n",
		"no_trailing_newline":    "#!/bin/sh\necho 'no trailing newline'",
		"bash_shebang":           "#!/usr/bin/env bash\necho 'bash hook'\n",
		"blank_lines_preserved":  "#!/bin/sh\n\necho 'after blank line'\n\n",
		"comments_only":          "#!/bin/sh\n# just a comment, no-op hook\n",
		"windows_style_ok_input": "#!/bin/sh\r\necho 'crlf line'\r\n",
	}
}

func TestSnapshot_UninstallRestoresExactOriginalBytes(t *testing.T) {
	for name, original := range existingHookVariants() {
		t.Run(name, func(t *testing.T) {
			dir := gitInitDir(t)
			hooksDir := filepath.Join(dir, ".git", "hooks")
			if err := os.MkdirAll(hooksDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hookPath(dir), []byte(original), 0o755); err != nil { //nolint:gosec // test: hook scripts must be executable
				t.Fatal(err)
			}

			if err := InstallGitHook(dir); err != nil {
				t.Fatalf("InstallGitHook: %v", err)
			}
			if err := UninstallGitHook(dir); err != nil {
				t.Fatalf("UninstallGitHook: %v", err)
			}

			got, err := os.ReadFile(hookPath(dir))
			if err != nil {
				t.Fatalf("hook should still exist after uninstall: %v", err)
			}
			if string(got) != original {
				t.Fatalf("hook not byte-exact after install+uninstall cycle:\n--- want ---\n%q\n--- got ---\n%q", original, got)
			}
		})
	}
}

func TestSnapshot_DoubleInstallUninstallCycleIsStable(t *testing.T) {
	dir := gitInitDir(t)
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	original := "#!/bin/sh\necho 'user hook'\n"
	if err := os.WriteFile(hookPath(dir), []byte(original), 0o755); err != nil { //nolint:gosec // test: hook scripts must be executable
		t.Fatal(err)
	}

	// Two full install/uninstall cycles must each restore the exact original.
	for cycle := 0; cycle < 2; cycle++ {
		if err := InstallGitHook(dir); err != nil {
			t.Fatalf("cycle %d: InstallGitHook: %v", cycle, err)
		}
		if err := UninstallGitHook(dir); err != nil {
			t.Fatalf("cycle %d: UninstallGitHook: %v", cycle, err)
		}
		got, err := os.ReadFile(hookPath(dir))
		if err != nil {
			t.Fatalf("cycle %d: hook missing: %v", cycle, err)
		}
		if string(got) != original {
			t.Fatalf("cycle %d: hook drifted from original:\n--- want ---\n%q\n--- got ---\n%q", cycle, original, got)
		}
	}
}

func TestSnapshot_UninstallOnlyOnlyOwnHookLeavesFileEmpty(t *testing.T) {
	// When the hook file was created entirely by envault (no prior user
	// content), uninstall must remove the file rather than leave an empty
	// or shebang-only file behind.
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}
	if err := UninstallGitHook(dir); err != nil {
		t.Fatalf("UninstallGitHook: %v", err)
	}
	if _, err := os.Stat(hookPath(dir)); !os.IsNotExist(err) {
		t.Fatal("expected hook file to be deleted, not left as an empty/shebang-only file")
	}
}

func TestSnapshot_UninstallDoesNotTouchUnrelatedHookFiles(t *testing.T) {
	dir := gitInitDir(t)
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}

	unrelated := filepath.Join(hooksDir, "pre-push")
	unrelatedContent := "#!/bin/sh\necho 'unrelated pre-push hook'\n"
	if err := os.WriteFile(unrelated, []byte(unrelatedContent), 0o755); err != nil { //nolint:gosec // test: hook scripts must be executable
		t.Fatal(err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}
	if err := UninstallGitHook(dir); err != nil {
		t.Fatalf("UninstallGitHook: %v", err)
	}

	got, err := os.ReadFile(unrelated)
	if err != nil {
		t.Fatalf("unrelated hook file was removed: %v", err)
	}
	if string(got) != unrelatedContent {
		t.Fatalf("unrelated hook file was modified:\n--- want ---\n%q\n--- got ---\n%q", unrelatedContent, got)
	}
}
