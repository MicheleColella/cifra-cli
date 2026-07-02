package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestRunInit_PrintsExpectedOutput(t *testing.T) {
	dir := t.TempDir()
	writeTestGitConfig(t, dir, "https://github.com/example/repo.git")

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runInit(dir, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		vault.DirName,
		"backend",
		"git",
		"https://github.com/example/repo.git",
		"No third-party server",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunInit_AlreadyInitialized(t *testing.T) {
	dir := t.TempDir()

	if err := runInit(dir, false); err != nil {
		t.Fatalf("first runInit: %v", err)
	}

	err := runInit(dir, false)
	if err == nil {
		t.Fatal("expected error on second init without --force")
	}
	if !strings.Contains(err.Error(), "already initialized") {
		t.Errorf("error = %q, want 'already initialized'", err.Error())
	}
}

func TestRunInit_Force(t *testing.T) {
	dir := t.TempDir()

	if err := runInit(dir, false); err != nil {
		t.Fatalf("first runInit: %v", err)
	}
	if err := runInit(dir, true); err != nil {
		t.Fatalf("force runInit: %v", err)
	}
}

func TestRunInit_NoGitRemote(t *testing.T) {
	dir := t.TempDir()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runInit(dir, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "none detected") {
		t.Errorf("expected 'none detected' when no git remote, got:\n%s", got)
	}
}

func writeTestGitConfig(t *testing.T, root, remoteURL string) {
	t.Helper()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	content := "[remote \"origin\"]\n\turl = " + remoteURL + "\n"
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(content), 0o600); err != nil {
		t.Fatalf("write .git/config: %v", err)
	}
}
