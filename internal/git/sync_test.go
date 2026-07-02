package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initBareRepo creates a bare git repository and returns its path.
func initBareRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := gitRun(dir, "init", "--bare", dir); err != nil {
		t.Fatalf("init bare repo: %v", err)
	}
	return dir
}

// cloneRepo clones bareRemote into a new temp directory, configures a
// test identity, and returns the working directory.
func cloneRepo(t *testing.T, bareRemote string) string {
	t.Helper()
	dir := t.TempDir()
	if err := gitRun(dir, "clone", bareRemote, dir); err != nil {
		t.Fatalf("clone repo: %v", err)
	}
	if err := gitRun(dir, "config", "user.email", "test@test.com"); err != nil {
		t.Fatalf("set user.email: %v", err)
	}
	if err := gitRun(dir, "config", "user.name", "Test"); err != nil {
		t.Fatalf("set user.name: %v", err)
	}
	return dir
}

// seedRemote creates an initial commit in the bare remote so clones have
// a branch to track.
func seedRemote(t *testing.T, bareRemote string) {
	t.Helper()
	seed := t.TempDir()
	if err := gitRun(seed, "clone", bareRemote, seed); err != nil {
		t.Fatalf("clone for seed: %v", err)
	}
	if err := gitRun(seed, "config", "user.email", "seed@test.com"); err != nil {
		t.Fatalf("seed user.email: %v", err)
	}
	if err := gitRun(seed, "config", "user.name", "Seed"); err != nil {
		t.Fatalf("seed user.name: %v", err)
	}
	readme := filepath.Join(seed, "README")
	if err := os.WriteFile(readme, []byte("envault test repo\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := gitRun(seed, "add", "README"); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	if err := gitRun(seed, "commit", "-m", "init"); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if err := gitRun(seed, "push", "origin", "HEAD"); err != nil {
		t.Fatalf("seed push: %v", err)
	}
}

// writeVaultFile creates a file inside <dir>/.envault/ with given content.
func writeVaultFile(t *testing.T, dir, name, content string) {
	t.Helper()
	vaultDir := filepath.Join(dir, ".envault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("mkdir .envault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}
}

func TestCommitVault_CreatesCommit(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "secrets.enc", `{"version":1,"entries":[]}`)

	hash, err := CommitVault(repo)
	if err != nil {
		t.Fatalf("CommitVault: %v", err)
	}
	if len(hash) == 0 {
		t.Error("expected non-empty commit hash")
	}

	// Verify the commit message.
	msg, err := gitOutput(repo, "log", "-1", "--format=%s")
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if strings.TrimSpace(msg) != "envault: sync encrypted secrets" {
		t.Errorf("unexpected commit message: %q", strings.TrimSpace(msg))
	}
}

func TestCommitVault_NothingToCommit(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "secrets.enc", `{"version":1,"entries":[]}`)

	// First commit succeeds.
	if _, err := CommitVault(repo); err != nil {
		t.Fatalf("first CommitVault: %v", err)
	}

	// Second commit with no changes returns ErrNothingToCommit.
	_, err := CommitVault(repo)
	if err != ErrNothingToCommit {
		t.Errorf("expected ErrNothingToCommit, got %v", err)
	}
}

func TestPushOrigin(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "secrets.enc", `{"version":1,"entries":[]}`)

	if _, err := CommitVault(repo); err != nil {
		t.Fatalf("CommitVault: %v", err)
	}

	if err := PushOrigin(repo); err != nil {
		t.Fatalf("PushOrigin: %v", err)
	}

	// Verify bare remote has the commit.
	out, err := gitOutput(bare, "log", "--oneline", "-1")
	if err != nil {
		t.Fatalf("bare git log: %v", err)
	}
	if !strings.Contains(out, "envault: sync encrypted secrets") {
		t.Errorf("commit not found in bare remote: %q", strings.TrimSpace(out))
	}
}

func TestFetchAndMergeOrigin(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)

	// Two independent clones of the same remote.
	repoA := cloneRepo(t, bare)
	repoB := cloneRepo(t, bare)

	// A commits and pushes a vault file.
	writeVaultFile(t, repoA, "secrets.enc", `{"version":1,"entries":[{"name":"KEY"}]}`)
	if _, err := CommitVault(repoA); err != nil {
		t.Fatalf("A CommitVault: %v", err)
	}
	if err := PushOrigin(repoA); err != nil {
		t.Fatalf("A PushOrigin: %v", err)
	}

	// B fetches and merges.
	if err := FetchOrigin(repoB); err != nil {
		t.Fatalf("B FetchOrigin: %v", err)
	}
	if err := MergeOrigin(repoB); err != nil {
		t.Fatalf("B MergeOrigin: %v", err)
	}

	// B should now have the file.
	content, err := os.ReadFile(filepath.Join(repoB, ".envault", "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc in B: %v", err)
	}
	if !strings.Contains(string(content), "KEY") {
		t.Errorf("merged file missing expected content: %q", string(content))
	}
}

func TestCurrentBranch(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	branch, err := CurrentBranch(repo)
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	// Typically "master" or "main" depending on git version defaults.
	if branch == "" {
		t.Error("expected non-empty branch name")
	}
}

func TestHeadHash(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	hash, err := HeadHash(repo)
	if err != nil {
		t.Fatalf("HeadHash: %v", err)
	}
	if len(hash) < 4 {
		t.Errorf("expected a non-trivial commit hash, got %q", hash)
	}
}

func TestIsVaultTracked_TrueAfterCommitAndPush(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "config", "backend = git\n")
	if _, err := CommitVault(repo); err != nil {
		t.Fatalf("CommitVault: %v", err)
	}

	if !IsVaultTracked(repo) {
		t.Error("expected .envault/config to be tracked after commit")
	}
}

func TestIsVaultTracked_FalseWhenUntracked(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "config", "backend = git\n")
	// Never committed — still untracked.

	if IsVaultTracked(repo) {
		t.Error("expected .envault/config to be untracked before any commit")
	}
}

func TestCleanVault_RemovesUntrackedFiles(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "secrets.enc", `{"version":1,"entries":[]}`)
	untracked := filepath.Join(repo, ".envault", "secrets.enc")
	if _, err := os.Stat(untracked); err != nil {
		t.Fatalf("expected untracked file to exist before clean: %v", err)
	}

	if err := CleanVault(repo); err != nil {
		t.Fatalf("CleanVault: %v", err)
	}
	if _, err := os.Stat(untracked); !os.IsNotExist(err) {
		t.Error("expected untracked vault file to be removed by CleanVault")
	}
}

func TestCleanVault_LeavesCommittedFilesIntact(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	writeVaultFile(t, repo, "config", "backend = git\n")
	if _, err := CommitVault(repo); err != nil {
		t.Fatalf("CommitVault: %v", err)
	}

	if err := CleanVault(repo); err != nil {
		t.Fatalf("CleanVault: %v", err)
	}

	committed := filepath.Join(repo, ".envault", "config")
	if _, err := os.Stat(committed); err != nil {
		t.Fatalf("expected committed vault file to survive CleanVault: %v", err)
	}
}

func TestMergeOrigin_FastForward(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repoA := cloneRepo(t, bare)
	repoB := cloneRepo(t, bare)

	writeVaultFile(t, repoA, "secrets.enc", `{"version":1,"entries":[{"name":"KEY"}]}`)
	if _, err := CommitVault(repoA); err != nil {
		t.Fatalf("A CommitVault: %v", err)
	}
	if err := PushOrigin(repoA); err != nil {
		t.Fatalf("A PushOrigin: %v", err)
	}

	if err := FetchOrigin(repoB); err != nil {
		t.Fatalf("B FetchOrigin: %v", err)
	}
	if err := MergeOrigin(repoB); err != nil {
		t.Fatalf("MergeOrigin: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(repoB, ".envault", "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc after merge: %v", err)
	}
	if !strings.Contains(string(content), "KEY") {
		t.Errorf("merged file missing expected content: %q", content)
	}
}

func TestMergeOrigin_ReturnsErrMergeConflict(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repoA := cloneRepo(t, bare)
	repoB := cloneRepo(t, bare)

	writeVaultFile(t, repoA, "secrets.enc", `{"version":1,"entries":[{"name":"FROM_A"}]}`)
	if _, err := CommitVault(repoA); err != nil {
		t.Fatalf("A CommitVault: %v", err)
	}
	if err := PushOrigin(repoA); err != nil {
		t.Fatalf("A PushOrigin: %v", err)
	}

	writeVaultFile(t, repoB, "secrets.enc", `{"version":1,"entries":[{"name":"FROM_B"}]}`)
	if _, err := CommitVault(repoB); err != nil {
		t.Fatalf("B CommitVault: %v", err)
	}
	if err := FetchOrigin(repoB); err != nil {
		t.Fatalf("B FetchOrigin: %v", err)
	}

	err := MergeOrigin(repoB)
	if err != ErrMergeConflict {
		t.Fatalf("expected ErrMergeConflict, got %v", err)
	}
}
