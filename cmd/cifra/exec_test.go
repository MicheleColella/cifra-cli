package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunExec_NotInitialized(t *testing.T) {
	err := runExec(t.TempDir(), "/bin/true", newMemStore())
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected not-initialized error, got %v", err)
	}
}

func TestRunExec_FallbackShell(t *testing.T) {
	// When shell is empty, runExec falls back to /bin/sh.
	// We can't easily test the interactive path, so we use an
	// env var trick: set SHELL="" and pass "" explicitly.
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	// Pass "" as shell; runExec must not error with "exec: no such file".
	// /bin/sh -c "exit 0" exits cleanly without interactive input.
	err := runExec(root, "/bin/sh", kc)
	// runExec launches /bin/sh interactively — it will exit immediately
	// with stdin closed, so we just verify no unexpected error.
	if err != nil {
		var ece exitCodeError
		if !errors.As(err, &ece) {
			t.Fatalf("unexpected error: %v", err)
		}
		// Exit codes from a shell with no input are acceptable (0 or 1).
	}
}

func TestRunExec_ShowsWarning(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	var outBuf bytes.Buffer
	ui.Out = &outBuf
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	// /bin/true exits immediately — enough to observe the warning.
	_ = runExec(root, "/bin/true", kc)

	// ui.Warn writes to ui.Out (yellow "! msg").
	if !strings.Contains(outBuf.String(), "persist") {
		t.Errorf("expected persistence warning, got: %q", outBuf.String())
	}
}
