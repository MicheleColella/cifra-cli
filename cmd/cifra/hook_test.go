package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/hook"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunHookInstallGit_InstallsHook(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", dir)

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallGit(dir); err != nil {
		t.Fatalf("runHookInstallGit: %v", err)
	}

	if !hook.IsGitHookInstalled(dir) {
		t.Error("hook not installed after runHookInstallGit")
	}
	if !strings.Contains(out.String(), "installed") {
		t.Errorf("expected 'installed' in output, got %q", out.String())
	}
}

func TestRunHookInstallGit_AlreadyInstalled(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", dir)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallGit(dir); err != nil {
		t.Fatalf("first install: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runHookInstallGit(dir); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already installed") {
		t.Errorf("expected 'already installed' on second call, got %q", out.String())
	}
}

func TestRunHookUninstallGit_RemovesHook(t *testing.T) {
	dir := t.TempDir()
	mustGit(t, dir, "init", dir)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallGit(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runHookUninstallGit(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if hook.IsGitHookInstalled(dir) {
		t.Error("hook still reported as installed after uninstall")
	}
}

func TestRunHookInstallGit_NotGitRepo(t *testing.T) {
	dir := t.TempDir() // no .git

	err := runHookInstallGit(dir)
	if err == nil {
		t.Fatal("expected error outside git repo, got nil")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("error = %q, want 'not a git repository'", err.Error())
	}
}

func TestHookCmd_InstallSubcommandRegistered(t *testing.T) {
	root := newRootCmd("dev")

	var hookCmd, installCmd bool
	for _, sub := range root.Commands() {
		if sub.Name() == "hook" {
			hookCmd = true
			for _, s := range sub.Commands() {
				if s.Name() == "install" {
					installCmd = true
				}
			}
		}
	}

	if !hookCmd {
		t.Error("hook command not registered on root")
	}
	if !installCmd {
		t.Error("hook install subcommand not registered")
	}
}

func TestHookInstallCmd_RequiresFlagSelection(t *testing.T) {
	root := newRootCmd("dev")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"hook", "install"}) // missing --git

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when no flag is given, got nil")
	}
	if !strings.Contains(err.Error(), "--git") {
		t.Errorf("error = %q, want mention of --git", err.Error())
	}
}
