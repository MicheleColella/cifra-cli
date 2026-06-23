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
	want := []string{"init", "key", "import", "add", "list", "push", "pull", "run", "hook"}

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

func TestStubCommandsReturnError(t *testing.T) {
	stubs := []string{"key", "import", "add", "list", "push", "pull", "run", "hook"}
	for _, name := range stubs {
		t.Run(name, func(t *testing.T) {
			root := newRootCmd("dev")
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs([]string{name})
			if err := root.Execute(); err == nil {
				t.Errorf("command %q: expected error, got nil", name)
			}
		})
	}
}

func TestStubErrorContainsCommandNameAndReason(t *testing.T) {
	root := newRootCmd("dev")
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"key"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error from stub command")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error = %q, want command name 'key'", err.Error())
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error = %q, want 'not implemented'", err.Error())
	}
}

func TestRootSilencesErrorOutput(t *testing.T) {
	var errBuf strings.Builder
	root := newRootCmd("dev")
	root.SetOut(io.Discard)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"key"})
	_ = root.Execute()

	// Cobra should not print the error itself (SilenceErrors: true)
	if strings.Contains(errBuf.String(), "Error:") {
		t.Errorf("root cmd printed cobra error prefix, SilenceErrors not working: %q", errBuf.String())
	}
}
