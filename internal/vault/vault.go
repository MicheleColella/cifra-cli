package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DirName is the vault directory created inside the repository root.
const DirName = ".cifra"

const (
	configFile     = "config"
	recipientsFile = "recipients"
)

// ErrAlreadyInitialized is returned by Init when the vault already exists
// and force is false.
var ErrAlreadyInitialized = errors.New("vault already initialized (use --force to reinitialize)")

// Config holds the vault configuration written to .cifra/config.
type Config struct {
	Backend string
	Remote  string
}

// Init creates the vault directory structure inside repoRoot.
// If the vault already exists and force is false, it returns ErrAlreadyInitialized.
func Init(repoRoot, remote string, force bool) (*Config, error) {
	vaultDir := filepath.Join(repoRoot, DirName)

	if _, err := os.Stat(vaultDir); err == nil && !force {
		return nil, ErrAlreadyInitialized
	}

	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault dir: %w", err)
	}

	cfg := &Config{Backend: "git", Remote: remote}
	if err := writeConfig(vaultDir, cfg); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	recipPath := filepath.Join(vaultDir, recipientsFile)
	if _, err := os.Stat(recipPath); os.IsNotExist(err) {
		if err := os.WriteFile(recipPath, []byte{}, 0o600); err != nil {
			return nil, fmt.Errorf("create recipients file: %w", err)
		}
	}

	return cfg, nil
}

// IsInitialized reports whether a vault directory exists inside repoRoot.
func IsInitialized(repoRoot string) bool {
	_, err := os.Stat(filepath.Join(repoRoot, DirName))
	return err == nil
}

func writeConfig(vaultDir string, cfg *Config) error {
	content := fmt.Sprintf("backend = %s\nremote = %s\n", cfg.Backend, cfg.Remote)
	return os.WriteFile(filepath.Join(vaultDir, configFile), []byte(content), 0o600)
}
