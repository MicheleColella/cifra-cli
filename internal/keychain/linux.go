//go:build linux

package keychain

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

type linuxStore struct{}

// New returns a Store backed by the Linux kernel keyring via keyctl(1).
func New() (Store, error) {
	if _, err := exec.LookPath("keyctl"); err != nil {
		return nil, fmt.Errorf("%w: 'keyctl' command not found (install keyutils)", ErrNotAvailable)
	}
	return &linuxStore{}, nil
}

// Seal stores privateKey in the user's kernel keyring under "cifra:<id>".
// Returns ErrAlreadyExists if a key already exists for id.
func (s *linuxStore) Seal(id string, privateKey []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	if s.exists(id) {
		return fmt.Errorf("%w: %s", ErrAlreadyExists, id)
	}
	encoded := base64.StdEncoding.EncodeToString(privateKey)
	// keyctl padd reads the key payload from stdin.
	cmd := exec.Command("keyctl", "padd", "user", keyName(id), "@u") //nolint:gosec // id validated by validateID above
	cmd.Stdin = strings.NewReader(encoded)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keyring store failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Unseal retrieves the private key for id from the kernel keyring.
func (s *linuxStore) Unseal(id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	search := exec.Command("keyctl", "search", "@u", "user", keyName(id)) //nolint:gosec // id validated above
	idOut, err := search.Output()
	if err != nil {
		return nil, ErrNotFound
	}
	keyID, err := parseKeyID(strings.TrimSpace(string(idOut)))
	if err != nil {
		return nil, err
	}
	print := exec.Command("keyctl", "print", keyID) //nolint:gosec // keyID is a numeric kernel serial, validated by parseKeyID
	out, err := print.Output()
	if err != nil {
		return nil, fmt.Errorf("keyring read failed: %w", err)
	}
	encoded := strings.TrimSpace(string(out))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode key from keyring: %w", err)
	}
	return key, nil
}

// Delete removes the keyring entry for id.
func (s *linuxStore) Delete(id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	search := exec.Command("keyctl", "search", "@u", "user", keyName(id)) //nolint:gosec // id validated above
	idOut, err := search.Output()
	if err != nil {
		return ErrNotFound
	}
	keyID, err := parseKeyID(strings.TrimSpace(string(idOut)))
	if err != nil {
		return err
	}
	cmd := exec.Command("keyctl", "unlink", keyID, "@u") //nolint:gosec // keyID is a numeric kernel serial, validated by parseKeyID
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keyring delete failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *linuxStore) exists(id string) bool {
	cmd := exec.Command("keyctl", "search", "@u", "user", keyName(id)) //nolint:gosec // callers must validate id first
	return cmd.Run() == nil
}

func keyName(id string) string {
	return "cifra:" + id
}
