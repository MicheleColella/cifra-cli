package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

// withTestAgent points the agent package's fixed socket at a short-path temp
// dir (see internal/agent's own tests for why t.TempDir() is too long on
// macOS) and starts a real agent server for the test.
func withTestAgent(t *testing.T) {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cifra-cmd-agent-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	oldHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", home)
	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.RemoveAll(home)
	})

	ln, err := agent.Listen()
	if err != nil {
		t.Fatalf("agent.Listen: %v", err)
	}
	go agent.Serve(ln)
	t.Cleanup(func() { _ = ln.Close() })
}

func TestRunAgentUnlock_Success(t *testing.T) {
	withTestAgent(t)

	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")
	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}

	silenceUI(t)

	if err := runAgentUnlock(root, kc, time.Minute); err != nil {
		t.Fatalf("runAgentUnlock: %v", err)
	}

	got, ok := agent.TryGet("alice@example.com")
	if !ok {
		t.Fatal("expected key to be cached in the agent after unlock")
	}
	if string(got) != string(priv[:]) {
		t.Error("cached key does not match the recipient's private key")
	}
}

func TestRunAgentUnlock_NoPrivateKey(t *testing.T) {
	withTestAgent(t)

	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	err := runAgentUnlock(root, newMemStore(), time.Minute)
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key' error, got %v", err)
	}
}

func TestRunAgentStatus_NoAgentRunning(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "cifra-cmd-agent-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	oldHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", home)
	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.RemoveAll(home)
	})

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAgentStatus(); err != nil {
		t.Fatalf("runAgentStatus: %v", err)
	}
	if !strings.Contains(out.String(), "No agent running") {
		t.Errorf("expected 'no agent running' message, got: %s", out.String())
	}
}

func TestRunAgentStatus_ReportsUnlockedKeys(t *testing.T) {
	withTestAgent(t)

	if err := agent.Unlock("alice@example.com", []byte("fake-32-byte-priv-key-padding.."), time.Minute); err != nil {
		t.Fatalf("agent.Unlock: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAgentStatus(); err != nil {
		t.Fatalf("runAgentStatus: %v", err)
	}
	if !strings.Contains(out.String(), "alice@example.com") {
		t.Errorf("expected alice@example.com in status output, got: %s", out.String())
	}
}
