package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit_CreatesVaultDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); err != nil {
		t.Errorf(".cifra dir not created: %v", err)
	}
}

func TestInit_WritesConfig(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Init(dir, "https://github.com/example/repo.git", false)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	if cfg.Backend != "git" {
		t.Errorf("Backend = %q, want git", cfg.Backend)
	}
	if cfg.Remote != "https://github.com/example/repo.git" {
		t.Errorf("Remote = %q, want https://github.com/example/repo.git", cfg.Remote)
	}

	data, err := os.ReadFile(filepath.Join(dir, DirName, configFile))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "backend = git") {
		t.Errorf("config missing backend line: %q", content)
	}
	if !strings.Contains(content, "remote = https://github.com/example/repo.git") {
		t.Errorf("config missing remote line: %q", content)
	}
}

func TestInit_CreatesRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, DirName, recipientsFile))
	if err != nil {
		t.Fatalf("recipients file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("recipients file not empty: size=%d", info.Size())
	}
}

func TestInit_VaultDirMode(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, DirName))
	if err != nil {
		t.Fatalf("stat vault dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("vault dir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestInit_AlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("first Init: %v", err)
	}

	_, err := Init(dir, "", false)
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("second Init: got %v, want ErrAlreadyInitialized", err)
	}
}

func TestInit_ForceReinitializes(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "old-remote", false); err != nil {
		t.Fatalf("first Init: %v", err)
	}

	cfg, err := Init(dir, "new-remote", true)
	if err != nil {
		t.Fatalf("force Init: %v", err)
	}
	if cfg.Remote != "new-remote" {
		t.Errorf("Remote = %q, want new-remote", cfg.Remote)
	}

	data, err := os.ReadFile(filepath.Join(dir, DirName, configFile))
	if err != nil {
		t.Fatalf("read config after force: %v", err)
	}
	if !strings.Contains(string(data), "remote = new-remote") {
		t.Errorf("config not updated after --force: %q", string(data))
	}
}

func TestIsInitialized(t *testing.T) {
	dir := t.TempDir()

	if IsInitialized(dir) {
		t.Error("IsInitialized = true before init, want false")
	}

	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if !IsInitialized(dir) {
		t.Error("IsInitialized = false after init, want true")
	}
}

func TestInit_RecipientsFilePreservedOnForce(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Simulate a populated recipients file.
	recipPath := filepath.Join(dir, DirName, recipientsFile)
	existing := "abc123pubkey\n"
	if err := os.WriteFile(recipPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	// --force should NOT overwrite the recipients file.
	if _, err := Init(dir, "", true); err != nil {
		t.Fatalf("force Init: %v", err)
	}

	data, err := os.ReadFile(recipPath)
	if err != nil {
		t.Fatalf("read recipients after force: %v", err)
	}
	if string(data) != existing {
		t.Errorf("recipients overwritten by --force: got %q, want %q", string(data), existing)
	}
}
