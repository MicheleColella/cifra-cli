package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitInitDir creates a temp dir, runs `git init`, and returns the path.
func gitInitDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("git", "init", dir) //nolint:gosec // test helper, dir is t.TempDir()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

func hookPath(dir string) string {
	return filepath.Join(dir, ".git", "hooks", "pre-commit")
}

// ---- InstallGitHook ----

func TestInstallGitHook_CreatesNewFile(t *testing.T) {
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}

	content, err := os.ReadFile(hookPath(dir))
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	s := string(content)

	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Error("new hook does not start with shebang")
	}
	if !strings.Contains(s, hookBeginMarker) {
		t.Error("new hook missing begin marker")
	}
	if !strings.Contains(s, hookEndMarker) {
		t.Error("new hook missing end marker")
	}
}

func TestInstallGitHook_FileIsExecutable(t *testing.T) {
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}

	info, err := os.Stat(hookPath(dir))
	if err != nil {
		t.Fatalf("stat hook: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("hook file is not executable")
	}
}

func TestInstallGitHook_AppendsToExistingHook(t *testing.T) {
	dir := gitInitDir(t)
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := "#!/bin/sh\necho 'my existing hook'\n"
	if err := os.WriteFile(hookPath(dir), []byte(existing), 0o755); err != nil { //nolint:gosec // test: hook scripts must be executable
		t.Fatal(err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}

	content, _ := os.ReadFile(hookPath(dir))
	s := string(content)

	if !strings.Contains(s, "my existing hook") {
		t.Error("existing hook content was removed")
	}
	if !strings.Contains(s, hookBeginMarker) {
		t.Error("envault block not appended")
	}
	// Existing shebang should appear only once.
	if strings.Count(s, "#!/bin/sh") != 1 {
		t.Errorf("shebang count = %d, want 1", strings.Count(s, "#!/bin/sh"))
	}
}

func TestInstallGitHook_Idempotent(t *testing.T) {
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("first install: %v", err)
	}
	content1, _ := os.ReadFile(hookPath(dir))

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("second install: %v", err)
	}
	content2, _ := os.ReadFile(hookPath(dir))

	if string(content1) != string(content2) {
		t.Error("second install modified the file (not idempotent)")
	}
}

func TestInstallGitHook_NotGitRepo(t *testing.T) {
	dir := t.TempDir() // no .git dir

	err := InstallGitHook(dir)
	if err == nil {
		t.Fatal("expected error for non-git-repo, got nil")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("error = %q, want 'not a git repository'", err.Error())
	}
}

// ---- UninstallGitHook ----

func TestUninstallGitHook_DeletesFileWhenCreatedByUs(t *testing.T) {
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := UninstallGitHook(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if _, err := os.Stat(hookPath(dir)); !os.IsNotExist(err) {
		t.Error("expected hook file to be deleted (was created entirely by envault)")
	}
}

func TestUninstallGitHook_PreservesExistingContent(t *testing.T) {
	dir := gitInitDir(t)
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := "#!/bin/sh\necho 'kept'\n"
	if err := os.WriteFile(hookPath(dir), []byte(existing), 0o755); err != nil { //nolint:gosec // test: hook scripts must be executable
		t.Fatal(err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := UninstallGitHook(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	content, err := os.ReadFile(hookPath(dir))
	if err != nil {
		t.Fatalf("hook should still exist: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "kept") {
		t.Error("existing content was removed on uninstall")
	}
	if strings.Contains(s, hookBeginMarker) {
		t.Error("envault block still present after uninstall")
	}
}

func TestUninstallGitHook_NoOpWhenNotInstalled(t *testing.T) {
	dir := gitInitDir(t)

	// No hook installed — should not error.
	if err := UninstallGitHook(dir); err != nil {
		t.Fatalf("uninstall when not installed: %v", err)
	}
}

// ---- IsGitHookInstalled ----

func TestIsGitHookInstalled_FalseBeforeInstall(t *testing.T) {
	dir := gitInitDir(t)
	if IsGitHookInstalled(dir) {
		t.Error("reported installed before any install")
	}
}

func TestIsGitHookInstalled_TrueAfterInstall(t *testing.T) {
	dir := gitInitDir(t)
	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !IsGitHookInstalled(dir) {
		t.Error("reported not installed after install")
	}
}

func TestIsGitHookInstalled_FalseAfterUninstall(t *testing.T) {
	dir := gitInitDir(t)
	_ = InstallGitHook(dir)
	_ = UninstallGitHook(dir)
	if IsGitHookInstalled(dir) {
		t.Error("reported installed after uninstall")
	}
}

// ---- resolveHooksDir ----

func TestInstallGitHook_RespectsCoreHooksPathRelative(t *testing.T) {
	dir := gitInitDir(t)
	if err := exec.Command("git", "-C", dir, "config", "--local", "core.hooksPath", "custom-hooks"). //nolint:gosec // test-controlled args
														Run(); err != nil {
		t.Fatalf("git config core.hooksPath: %v", err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}

	customPath := filepath.Join(dir, "custom-hooks", "pre-commit")
	content, err := os.ReadFile(customPath)
	if err != nil {
		t.Fatalf("expected hook at custom core.hooksPath location: %v", err)
	}
	if !strings.Contains(string(content), hookBeginMarker) {
		t.Error("hook at custom path missing envault block")
	}

	// The default .git/hooks/pre-commit must NOT have been touched.
	if _, err := os.Stat(hookPath(dir)); !os.IsNotExist(err) {
		t.Error("expected no hook written to the default .git/hooks path")
	}
}

func TestInstallGitHook_RespectsCoreHooksPathAbsolute(t *testing.T) {
	dir := gitInitDir(t)
	absHooks := filepath.Join(t.TempDir(), "hooks")
	if err := exec.Command("git", "-C", dir, "config", "--local", "core.hooksPath", absHooks). //nolint:gosec // test-controlled args
													Run(); err != nil {
		t.Fatalf("git config core.hooksPath: %v", err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(absHooks, "pre-commit"))
	if err != nil {
		t.Fatalf("expected hook at absolute core.hooksPath location: %v", err)
	}
	if !strings.Contains(string(content), hookBeginMarker) {
		t.Error("hook at absolute custom path missing envault block")
	}
}

// ---- stripEnvaultBlock ----

func TestStripEnvaultBlock_RemovesBlockAndSeparator(t *testing.T) {
	content := "#!/bin/sh\nexisting\n\n" + envaultBlock
	result := stripEnvaultBlock(content)

	if strings.Contains(result, hookBeginMarker) {
		t.Error("begin marker still present after strip")
	}
	if strings.Contains(result, hookEndMarker) {
		t.Error("end marker still present after strip")
	}
	if !strings.Contains(result, "existing") {
		t.Error("existing content was removed by strip")
	}
	// Blank separator line before block should be removed.
	if strings.Contains(result, "\n\n") {
		t.Error("trailing blank line from separator remained")
	}
}

func TestStripEnvaultBlock_EmptyWhenOnlyBlock(t *testing.T) {
	content := "#!/bin/sh\n" + envaultBlock
	result := stripEnvaultBlock(content)
	if strings.TrimSpace(result) != "#!/bin/sh" {
		t.Errorf("expected only shebang after strip, got %q", result)
	}
}

// ---- upgrade (v1 → v2) ----

func TestInstallGitHook_UpgradesV1Block(t *testing.T) {
	dir := gitInitDir(t)

	// Simulate a v1 block (no version marker) already installed.
	v1Block := hookBeginMarker + "\n# Envault: old v1 script\n" + hookEndMarker + "\n"
	v1Content := "#!/bin/sh\n" + v1Block
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath(dir), []byte(v1Content), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook upgrade: %v", err)
	}

	content, _ := os.ReadFile(hookPath(dir))
	s := string(content)

	if !strings.Contains(s, hookVersionMarker) {
		t.Error("upgraded hook should contain version marker")
	}
	if strings.Contains(s, "old v1 script") {
		t.Error("v1 script body should have been replaced")
	}
	// Only one envault block should be present.
	if strings.Count(s, hookBeginMarker) != 1 {
		t.Errorf("expected 1 begin marker after upgrade, got %d", strings.Count(s, hookBeginMarker))
	}
}

func TestInstallGitHook_IdempotentV2(t *testing.T) {
	dir := gitInitDir(t)

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("first install: %v", err)
	}
	content1, _ := os.ReadFile(hookPath(dir))

	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("second install: %v", err)
	}
	content2, _ := os.ReadFile(hookPath(dir))

	if string(content1) != string(content2) {
		t.Error("second install of v2 hook modified the file (not idempotent)")
	}
}

func TestInstallGitHook_NewHookContainsVersionMarker(t *testing.T) {
	dir := gitInitDir(t)
	if err := InstallGitHook(dir); err != nil {
		t.Fatalf("InstallGitHook: %v", err)
	}
	content, _ := os.ReadFile(hookPath(dir))
	if !strings.Contains(string(content), hookVersionMarker) {
		t.Error("new hook missing version marker")
	}
}
