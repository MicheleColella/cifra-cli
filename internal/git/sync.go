package git

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrNothingToCommit is returned by CommitVault when .cifra/ has no
// staged changes — the vault is already in sync with the last commit.
var ErrNothingToCommit = errors.New("nothing to commit")

// CommitVault stages all .cifra/ files and creates a commit with the
// canonical message "cifra: sync encrypted secrets". It returns the
// short (7-char) commit hash. If there are no changes it returns
// ErrNothingToCommit so the caller can still push unpushed commits.
func CommitVault(repoRoot string) (string, error) {
	if err := gitRun(repoRoot, "add", ".cifra/"); err != nil {
		return "", fmt.Errorf("stage vault: %w", err)
	}

	// exit 0 = no staged diff = nothing to commit
	chk := exec.Command("git", "diff", "--cached", "--quiet", ".cifra/")
	chk.Dir = repoRoot
	if err := chk.Run(); err == nil {
		return "", ErrNothingToCommit
	}

	if err := gitRun(repoRoot, "commit", "-m", "cifra: sync encrypted secrets"); err != nil {
		return "", fmt.Errorf("commit vault: %w", err)
	}

	hash, err := gitOutput(repoRoot, "rev-parse", "--short", "HEAD")
	if err != nil {
		return "", fmt.Errorf("read commit hash: %w", err)
	}
	return strings.TrimSpace(hash), nil
}

// HeadHash returns the short hash of the current HEAD commit.
func HeadHash(repoRoot string) (string, error) {
	out, err := gitOutput(repoRoot, "rev-parse", "--short", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// PushOrigin pushes HEAD to the origin remote.
func PushOrigin(repoRoot string) error {
	if err := gitRun(repoRoot, "push", "origin", "HEAD"); err != nil {
		return fmt.Errorf("push to origin: %w", err)
	}
	return nil
}

// FetchOrigin fetches from the origin remote.
func FetchOrigin(repoRoot string) error {
	if err := gitRun(repoRoot, "fetch", "origin"); err != nil {
		return fmt.Errorf("fetch from origin: %w", err)
	}
	return nil
}

// IsVaultTracked reports whether .cifra/config is known to git (i.e., the
// vault was cloned from a remote rather than only created locally). When this
// returns false the vault files are untracked and were never committed.
func IsVaultTracked(repoRoot string) bool {
	cmd := exec.Command("git", "ls-files", "--error-unmatch", ".cifra/config")
	cmd.Dir = repoRoot
	return cmd.Run() == nil
}

// CleanVault removes untracked files under .cifra/ so a fast-forward merge
// is not blocked by "untracked working tree files would be overwritten".
// Files already committed to git are left untouched.
func CleanVault(repoRoot string) error {
	if err := gitRun(repoRoot, "clean", "-fd", ".cifra/"); err != nil {
		return fmt.Errorf("clean vault: %w", err)
	}
	return nil
}

// MergeOrigin merges origin/<current-branch> into HEAD. Fast-forwards when
// possible; creates a merge commit for diverged histories. Returns
// ErrMergeConflict when the merge leaves unresolved conflicts so the caller
// can apply application-level resolution before calling ContinueMerge or AbortMerge.
func MergeOrigin(repoRoot string) error {
	branch, err := CurrentBranch(repoRoot)
	if err != nil {
		return fmt.Errorf("detect current branch: %w", err)
	}
	if err := gitRun(repoRoot, "merge", "--no-edit", "origin/"+branch); err != nil {
		// Distinguish conflict (resolvable) from a fatal git error.
		conflicts, _ := ConflictedFiles(repoRoot)
		if len(conflicts) > 0 {
			return ErrMergeConflict
		}
		return fmt.Errorf("merge from origin/%s: %w", branch, err)
	}
	return nil
}

// CurrentBranch returns the name of the currently checked-out branch.
func CurrentBranch(repoRoot string) (string, error) {
	out, err := gitOutput(repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// gitRun runs a git subcommand inside dir, returning a descriptive error
// that includes git's stderr output on failure.
func gitRun(dir string, args ...string) error {
	cmd := exec.Command("git", args...) //nolint:gosec // args are always hardcoded call sites
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// gitOutput runs a git subcommand inside dir and returns its stdout.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // args are always hardcoded call sites
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
