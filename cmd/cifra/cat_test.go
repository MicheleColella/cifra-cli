package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunCat_DecryptsSecret(t *testing.T) {
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

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runCat(root, "API_KEY", kc, false); err != nil {
		t.Fatalf("runCat: %v", err)
	}

	if !strings.Contains(out.String(), "s3cr3t") {
		t.Errorf("expected decrypted value in output, got: %s", out.String())
	}
}

func TestRunCat_NotFound(t *testing.T) {
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

	err := runCat(root, "NONEXISTENT", kc, false)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got %v", err)
	}
}

func TestRunCat_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir()
	kc := newMemStore()

	err := runCat(root, "KEY", kc, false)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunCat_NoMatchingKeyInKeychain(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	kc := newMemStore() // empty — alice's key is not in this keychain

	err := runCat(root, "API_KEY", kc, false)
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key' error, got %v", err)
	}
}

func TestRunCat_WarningGoesToStderr(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	var stdout, stderr bytes.Buffer
	ui.Out = &stdout
	ui.Err = &stderr
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	stdout.Reset()
	stderr.Reset()

	if err := runCat(root, "API_KEY", kc, false); err != nil {
		t.Fatalf("runCat: %v", err)
	}

	if !strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("expected WARNING on stderr, got: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "WARNING") {
		t.Error("WARNING must not appear on stdout")
	}
}

func TestRunCat_AgentModeBlocksOutput(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	ui.AgentMode = true
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	err := runCat(root, "API_KEY", kc, false)
	if err == nil {
		t.Fatal("expected error in agent mode, got nil")
	}
	if !strings.Contains(err.Error(), "agent mode") {
		t.Errorf("error should mention agent mode, got: %v", err)
	}
}

func TestRunCat_AgentModeForceAllows(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	ui.AgentMode = true
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	if err := runAdd(root, "API_KEY", []byte("s3cr3t")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runCat(root, "API_KEY", kc, true); err != nil {
		t.Fatalf("runCat with --force: %v", err)
	}

	if !strings.Contains(out.String(), "s3cr3t") {
		t.Errorf("expected decrypted value with --force, got: %s", out.String())
	}
}

func TestRunExport_DecryptsAllSecrets(t *testing.T) {
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

	for _, kv := range [][2]string{{"API_KEY", "s3cr3t"}, {"DB_URL", "postgres://localhost/db"}} {
		if err := runAdd(root, kv[0], []byte(kv[1])); err != nil {
			t.Fatalf("runAdd %s: %v", kv[0], err)
		}
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runExport(root, kc, false); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "API_KEY=s3cr3t") {
		t.Errorf("expected API_KEY=s3cr3t in output, got: %s", got)
	}
	if !strings.Contains(got, "DB_URL=postgres://localhost/db") {
		t.Errorf("expected DB_URL in output, got: %s", got)
	}
}

func TestRunExport_EmptyVault(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	var out bytes.Buffer
	ui.Out = &out
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runExport(root, newMemStore(), false); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	if !strings.Contains(out.String(), "no env secrets") {
		t.Errorf("expected 'no env secrets' message, got: %s", out.String())
	}
}

func TestRunExport_RequiresInitializedVault(t *testing.T) {
	root := t.TempDir()

	err := runExport(root, newMemStore(), false)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected 'not initialized' error, got %v", err)
	}
}

func TestRunExport_WarningGoesToStderr(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	var stdout, stderr bytes.Buffer
	ui.Out = &stdout
	ui.Err = &stderr
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	stdout.Reset()
	stderr.Reset()

	if err := runExport(root, kc, false); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	if !strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("expected WARNING on stderr, got: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "WARNING") {
		t.Error("WARNING must not appear on stdout")
	}
}

func TestRunExport_AgentModeBlocksOutput(t *testing.T) {
	root := initVaultRoot(t)

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	ui.AgentMode = true
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	err := runExport(root, newMemStore(), false)
	if err == nil {
		t.Fatal("expected error in agent mode, got nil")
	}
	if !strings.Contains(err.Error(), "agent mode") {
		t.Errorf("error should mention agent mode, got: %v", err)
	}
}
