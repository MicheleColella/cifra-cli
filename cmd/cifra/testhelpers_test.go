package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// mustGit runs a git subcommand inside dir and fatals on error.
func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test helper with hardcoded command
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out.String())
	}
}

// initTestRepo creates a bare remote, seeds it with an initial commit, clones
// it into a working directory with user identity set, and returns (workDir, bareDir).
func initTestRepo(t *testing.T, email, name string) (string, string) {
	t.Helper()

	bare := t.TempDir()
	mustGit(t, bare, "init", "--bare", bare)

	seed := t.TempDir()
	mustGit(t, seed, "clone", bare, seed)
	mustGit(t, seed, "config", "user.email", "seed@test.com")
	mustGit(t, seed, "config", "user.name", "Seed")
	if err := os.WriteFile(seed+"/README", []byte("test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustGit(t, seed, "add", "README")
	mustGit(t, seed, "commit", "-m", "init")
	mustGit(t, seed, "push", "origin", "HEAD")

	repo := t.TempDir()
	mustGit(t, repo, "clone", bare, repo)
	mustGit(t, repo, "config", "user.email", email)
	mustGit(t, repo, "config", "user.name", name)

	return repo, bare
}
