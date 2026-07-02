//go:build darwin

package keychain

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

const service = "cifra"

type macOSStore struct{}

// New returns a Store backed by macOS Keychain via the security(1) CLI.
func New() (Store, error) {
	if _, err := exec.LookPath("security"); err != nil {
		return nil, fmt.Errorf("%w: 'security' command not found", ErrNotAvailable)
	}
	return &macOSStore{}, nil
}

// Seal stores privateKey in the macOS Keychain under service/id.
// Returns ErrAlreadyExists if a key already exists for id.
func (s *macOSStore) Seal(id string, privateKey []byte) error {
	if s.exists(id) {
		return fmt.Errorf("%w: %s", ErrAlreadyExists, id)
	}
	encoded := base64.StdEncoding.EncodeToString(privateKey)
	// Note: -w passes the value as a process argument (briefly visible in `ps`).
	// The private key is base64-encoded and the exposure window is milliseconds.
	// This is the standard approach for CGO_ENABLED=0 macOS Keychain access.
	cmd := exec.Command("security", "add-generic-password", //nolint:gosec // id is user-supplied identity, not attacker-controlled
		"-s", service,
		"-a", id,
		"-w", encoded)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain store failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Unseal retrieves the private key for id from the macOS Keychain.
func (s *macOSStore) Unseal(id string) ([]byte, error) {
	cmd := exec.Command("security", "find-generic-password", //nolint:gosec
		"-s", service,
		"-a", id,
		"-w")
	out, err := cmd.Output()
	if err != nil {
		return nil, ErrNotFound
	}
	encoded := strings.TrimSpace(string(out))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode key from keychain: %w", err)
	}
	return key, nil
}

// Delete removes the keychain item for id.
func (s *macOSStore) Delete(id string) error {
	cmd := exec.Command("security", "delete-generic-password", //nolint:gosec
		"-s", service,
		"-a", id)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain delete failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *macOSStore) exists(id string) bool {
	cmd := exec.Command("security", "find-generic-password", "-s", service, "-a", id) //nolint:gosec
	return cmd.Run() == nil
}
