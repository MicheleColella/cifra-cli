package main

import (
	"io"
	"strings"
	"testing"
)

func TestRootVersion(t *testing.T) {
	cmd := newRootCmd("1.2.3")
	if cmd.Version != "1.2.3" {
		t.Errorf("version = %q, want %q", cmd.Version, "1.2.3")
	}
}

func TestRootCommandsRegistered(t *testing.T) {
	cmd := newRootCmd("dev")
	want := []string{"init", "key", "import", "add", "data", "set", "rm", "list", "cat", "export", "push", "pull", "rotate", "run", "exec", "hook", "scan", "status", "agent-check"}

	registered := make(map[string]bool)
	for _, c := range cmd.Commands() {
		registered[c.Name()] = true
	}

	for _, name := range want {
		if !registered[name] {
			t.Errorf("command %q not registered", name)
		}
	}
}

func TestRootSilencesErrorOutput(t *testing.T) {
	var errBuf strings.Builder
	root := newRootCmd("dev")
	root.SetOut(io.Discard)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"run"})
	_ = root.Execute()

	// Cobra should not print the error itself (SilenceErrors: true)
	if strings.Contains(errBuf.String(), "Error:") {
		t.Errorf("root cmd printed cobra error prefix, SilenceErrors not working: %q", errBuf.String())
	}
}
