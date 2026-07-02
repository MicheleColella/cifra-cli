package main

import (
	"os"
	"testing"
	"time"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
)

func TestAgentAwareStore_PrefersAgentOverInner(t *testing.T) {
	withTestAgent(t)

	if err := agent.Unlock("alice@example.com", []byte("agent-cached-key"), time.Minute); err != nil {
		t.Fatalf("agent.Unlock: %v", err)
	}

	inner := newMemStore()
	if err := inner.Seal("alice@example.com", []byte("inner-keychain-key")); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}

	store := &agentAwareStore{inner: inner}
	got, err := store.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(got) != "agent-cached-key" {
		t.Errorf("expected the agent's cached key to win, got %q", got)
	}
}

func TestAgentAwareStore_FallsBackToInner(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "cifra-keychain-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	oldHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", home)
	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.RemoveAll(home)
	})
	// No agent running — TryGet must fail closed and inner must be used.

	inner := newMemStore()
	if err := inner.Seal("bob@example.com", []byte("inner-keychain-key")); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}

	store := &agentAwareStore{inner: inner}
	got, err := store.Unseal("bob@example.com")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if string(got) != "inner-keychain-key" {
		t.Errorf("expected inner's key, got %q", got)
	}
}

func TestAgentAwareStore_SealDeletePassThrough(t *testing.T) {
	inner := newMemStore()
	store := &agentAwareStore{inner: inner}

	if err := store.Seal("carol@example.com", []byte("k")); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := inner.Unseal("carol@example.com"); err != nil {
		t.Errorf("expected Seal to reach inner, got: %v", err)
	}

	if err := store.Delete("carol@example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := inner.Unseal("carol@example.com"); err != keychain.ErrNotFound {
		t.Errorf("expected Delete to reach inner, got: %v", err)
	}
}
