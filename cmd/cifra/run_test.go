package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestRunRun_NotInitialized(t *testing.T) {
	err := runRun(t.TempDir(), []string{"echo", "hi"}, newMemStore(), runFilter{})
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected not-initialized error, got %v", err)
	}
}

func TestRunRun_NoPrivateKey(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	err := runRun(root, []string{"true"}, newMemStore(), runFilter{})
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key' error, got %v", err)
	}
}

func TestRunRun_InjectsSecrets(t *testing.T) {
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

	if err := runAdd(root, "CIFRA_TEST_VAR", []byte("hello-from-vault")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	var childOut bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runRun(root, []string{"printenv", "CIFRA_TEST_VAR"}, kc, runFilter{})

	_ = w.Close()
	_, _ = childOut.ReadFrom(r)
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("runRun: %v", err)
	}
	if !strings.Contains(childOut.String(), "hello-from-vault") {
		t.Errorf("expected secret value in child output, got: %q", childOut.String())
	}
}

func TestRunRun_ExitCodePropagated(t *testing.T) {
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

	err := runRun(root, []string{"false"}, kc, runFilter{})
	if err == nil {
		t.Fatal("expected exit-code error from 'false', got nil")
	}
	var ece exitCodeError
	if !errors.As(err, &ece) {
		t.Fatalf("expected exitCodeError, got %T: %v", err, err)
	}
	if ece.code != 1 {
		t.Errorf("exit code = %d, want 1", ece.code)
	}
}

func TestRunRun_EmptyVault(t *testing.T) {
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

	if err := runRun(root, []string{"true"}, kc, runFilter{}); err != nil {
		t.Fatalf("runRun with empty vault: %v", err)
	}
}

func TestRunRun_FileEntriesNotInjected(t *testing.T) {
	root := initVaultRoot(t)
	priv, pub, _ := envcrypto.GenerateKeyPair()
	if err := vault.AddRecipient(root, vault.Recipient{ID: "alice@example.com", PublicKey: pub}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

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

	keys := []envcrypto.PublicKey{pub}
	ids := []string{"alice@example.com"}
	entry, err := sealEntry("secret.pem", vault.KindFile, []byte("pem-content"), keys, ids)
	if err != nil {
		t.Fatalf("sealEntry file: %v", err)
	}
	store, _ := vault.LoadStore(root)
	store = store.Upsert(entry)
	if err := vault.SaveStore(root, store); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	var childOut bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runErr := runRun(root, []string{"env"}, kc, runFilter{})

	_ = w.Close()
	_, _ = childOut.ReadFrom(r)
	os.Stdout = oldStdout

	if runErr != nil {
		t.Fatalf("runRun: %v", runErr)
	}
	if strings.Contains(childOut.String(), "secret.pem") {
		t.Error("KindFile entry was injected as env var — it must not be")
	}
}

func TestRunRun_InfoOutput(t *testing.T) {
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

	if err := runAdd(root, "MY_SECRET", []byte("value")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	outBuf.Reset()
	if err := runRun(root, []string{"true"}, kc, runFilter{}); err != nil {
		t.Fatalf("runRun: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "decrypting") {
		t.Errorf("missing 'decrypting' in output: %q", out)
	}
	if !strings.Contains(out, "0 bytes written to disk") {
		t.Errorf("missing '0 bytes written to disk' in output: %q", out)
	}
}

func TestRunRun_OnlyFilter(t *testing.T) {
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

	if err := runAdd(root, "WANTED", []byte("yes")); err != nil {
		t.Fatalf("runAdd WANTED: %v", err)
	}
	if err := runAdd(root, "UNWANTED", []byte("no")); err != nil {
		t.Fatalf("runAdd UNWANTED: %v", err)
	}

	var childOut bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runErr := runRun(root, []string{"env"}, kc, runFilter{only: []string{"WANTED"}})

	_ = w.Close()
	_, _ = childOut.ReadFrom(r)
	os.Stdout = oldStdout

	if runErr != nil {
		t.Fatalf("runRun: %v", runErr)
	}
	out := childOut.String()
	if !strings.Contains(out, "WANTED=yes") {
		t.Errorf("WANTED key missing from child env: %q", out)
	}
	if strings.Contains(out, "UNWANTED=no") {
		t.Errorf("UNWANTED key must not appear with --only filter, but got: %q", out)
	}
}

func TestRunRun_ExceptFilter(t *testing.T) {
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

	if err := runAdd(root, "KEEP", []byte("keep-value")); err != nil {
		t.Fatalf("runAdd KEEP: %v", err)
	}
	if err := runAdd(root, "SKIP", []byte("skip-value")); err != nil {
		t.Fatalf("runAdd SKIP: %v", err)
	}

	var childOut bytes.Buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runErr := runRun(root, []string{"env"}, kc, runFilter{except: []string{"SKIP"}})

	_ = w.Close()
	_, _ = childOut.ReadFrom(r)
	os.Stdout = oldStdout

	if runErr != nil {
		t.Fatalf("runRun: %v", runErr)
	}
	out := childOut.String()
	if !strings.Contains(out, "KEEP=keep-value") {
		t.Errorf("KEEP key missing from child env: %q", out)
	}
	if strings.Contains(out, "SKIP=skip-value") {
		t.Errorf("SKIP key must not appear with --except filter, but got: %q", out)
	}
}

func TestToSet_Empty(t *testing.T) {
	if toSet(nil) != nil {
		t.Error("toSet(nil) should return nil")
	}
	if toSet([]string{}) != nil {
		t.Error("toSet([]) should return nil")
	}
}

func TestToSet_Basic(t *testing.T) {
	s := toSet([]string{"A", " B ", "C"})
	for _, k := range []string{"A", "B", "C"} {
		if _, ok := s[k]; !ok {
			t.Errorf("toSet missing %q", k)
		}
	}
}
