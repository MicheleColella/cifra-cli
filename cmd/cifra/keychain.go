package main

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
)

// passphraseEnv lets non-interactive callers (CI) supply the keychain passphrase
// without a TTY prompt. It is LESS SECURE than interactive entry: environment
// variables are visible to other same-user processes (e.g. via /proc or `ps -E`)
// and may be captured by shell history or process inspection. Use only in CI.
const passphraseEnv = "CIFRA_PASSPHRASE" //nolint:gosec // G101 false positive: this is the env var NAME, not a credential value

// openKeychain returns the OS keychain wrapped in the passphrase-protection
// decorator, further wrapped in an agent-aware decorator. Every private key
// is encrypted under a passphrase-derived KEK before it reaches the OS
// secret store, so a silently extracted blob is useless ciphertext.
func openKeychain() (keychain.Store, error) {
	inner, err := keychain.New()
	if err != nil {
		return nil, err
	}
	return &agentAwareStore{inner: keychain.NewProtected(inner, askPassphrase)}, nil
}

// openRawKeychain returns the unwrapped OS-backend keychain — no passphrase
// protection, no agent. Only `cifra key reseal` uses this: keychain.Reseal
// needs raw, unprotected access to stage a resealed blob under a temp id
// before touching the real one (see internal/keychain/reseal.go).
func openRawKeychain() (keychain.Store, error) {
	return keychain.New()
}

// agentAwareStore tries the cifra key-unlock agent (internal/agent) before
// falling back to inner unchanged. Only Unseal is intercepted — Seal/Delete
// manage the OS keychain itself and have nothing to do with the agent's
// in-memory cache. When no agent is running, or it doesn't have this id
// cached, TryGet fails closed and inner handles the request exactly as
// before the agent existed — this is a pure, optional fast path.
type agentAwareStore struct {
	inner keychain.Store
}

func (a *agentAwareStore) Unseal(id string) ([]byte, error) {
	if key, ok := agent.TryGet(id); ok {
		return key, nil
	}
	return a.inner.Unseal(id)
}

func (a *agentAwareStore) Seal(id string, data []byte) error { return a.inner.Seal(id, data) }
func (a *agentAwareStore) Delete(id string) error            { return a.inner.Delete(id) }

// askPassphrase obtains the keychain passphrase, preferring the CIFRA_PASSPHRASE
// environment variable (for CI) and falling back to a hidden interactive prompt.
func askPassphrase(prompt string) ([]byte, error) {
	if env := os.Getenv(passphraseEnv); env != "" {
		return []byte(env), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf(
			"no passphrase available: set %s or run interactively to unlock the keychain",
			passphraseEnv,
		)
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	return pass, nil
}
