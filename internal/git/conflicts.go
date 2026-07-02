package git

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrMergeConflict is returned by MergeOrigin when the merge produces
// unresolved conflicts. Inspect the working tree, call resolveSecretsConflict,
// then ContinueMerge — or AbortMerge to restore the pre-merge state.
var ErrMergeConflict = errors.New("merge conflict")

// ConflictedFiles returns the repo-root-relative paths of all files that have
// unresolved merge conflicts (i.e., appear as "UU" in the index).
func ConflictedFiles(repoRoot string) ([]string, error) {
	out, err := gitOutput(repoRoot, "diff", "--name-only", "--diff-filter=U")
	if err != nil {
		return nil, fmt.Errorf("list conflicted files: %w", err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// ConflictStage returns the raw bytes of path at the given merge stage.
// stage 1 = common ancestor (base), 2 = ours, 3 = theirs.
// Returns nil bytes (and nil error) when the file did not exist at that stage.
func ConflictStage(repoRoot string, stage int, path string) ([]byte, error) {
	ref := fmt.Sprintf(":%d:%s", stage, path)
	cmd := exec.Command("git", "show", ref) //nolint:gosec // stage and path are caller-controlled
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Treat "file not present at this stage" as a legitimate absent case.
		// All other errors (missing git binary, corrupt object DB, wrong dir) are propagated.
		msg := stderr.String()
		if strings.Contains(msg, "does not exist in the index") ||
			strings.Contains(msg, "exists on disk, but not in") ||
			strings.Contains(msg, "does not exist (neither on disk nor in the index)") ||
			strings.Contains(msg, "is in the index, but not at stage") {
			return nil, nil
		}
		return nil, fmt.Errorf("git show %s: %w: %s", ref, err, strings.TrimSpace(msg))
	}
	return stdout.Bytes(), nil
}

// StageFile runs `git add <path>` inside repoRoot, marking the file as resolved.
func StageFile(repoRoot, path string) error {
	if err := gitRun(repoRoot, "add", path); err != nil {
		return fmt.Errorf("stage %s: %w", path, err)
	}
	return nil
}

// ContinueMerge commits the in-progress merge using the auto-generated message.
func ContinueMerge(repoRoot string) error {
	if err := gitRun(repoRoot, "-c", "core.editor=true", "merge", "--continue"); err != nil {
		return fmt.Errorf("continue merge: %w", err)
	}
	return nil
}

// AbortMerge aborts an in-progress merge and restores the pre-merge state.
func AbortMerge(repoRoot string) error {
	if err := gitRun(repoRoot, "merge", "--abort"); err != nil {
		return fmt.Errorf("abort merge: %w", err)
	}
	return nil
}
