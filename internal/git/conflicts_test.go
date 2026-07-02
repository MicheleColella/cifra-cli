package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeDivergedMergeConflict sets up two clones of the same remote that both
// modify the same vault file differently, then triggers a real merge
// conflict in repoB by fetching and merging repoA's push. Returns repoB's
// path (with an in-progress conflicted merge) and the conflicted file's
// repo-relative path.
func makeDivergedMergeConflict(t *testing.T) (repoB string, conflictPath string) {
	t.Helper()
	bare := initBareRepo(t)
	seedRemote(t, bare)

	repoA := cloneRepo(t, bare)
	repoB = cloneRepo(t, bare)

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
	branch, err := CurrentBranch(repoB)
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	// This merge is expected to conflict — ignore the error and rely on
	// ConflictedFiles/git status to confirm the conflicted state below.
	_ = gitRun(repoB, "merge", "--no-edit", "origin/"+branch)

	return repoB, ".envault/secrets.enc"
}

func TestConflictedFiles_ReportsConflict(t *testing.T) {
	repo, path := makeDivergedMergeConflict(t)

	files, err := ConflictedFiles(repo)
	if err != nil {
		t.Fatalf("ConflictedFiles: %v", err)
	}
	found := false
	for _, f := range files {
		if f == path {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in conflicted files, got %v", path, files)
	}
}

func TestConflictedFiles_NoneWhenClean(t *testing.T) {
	bare := initBareRepo(t)
	seedRemote(t, bare)
	repo := cloneRepo(t, bare)

	files, err := ConflictedFiles(repo)
	if err != nil {
		t.Fatalf("ConflictedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no conflicted files, got %v", files)
	}
}

func TestConflictStage_ReadsOursAndTheirs(t *testing.T) {
	repo, path := makeDivergedMergeConflict(t)

	ours, err := ConflictStage(repo, 2, path)
	if err != nil {
		t.Fatalf("ConflictStage(ours): %v", err)
	}
	if !strings.Contains(string(ours), "FROM_B") {
		t.Errorf("stage 2 (ours) = %q, want to contain FROM_B", ours)
	}

	theirs, err := ConflictStage(repo, 3, path)
	if err != nil {
		t.Fatalf("ConflictStage(theirs): %v", err)
	}
	if !strings.Contains(string(theirs), "FROM_A") {
		t.Errorf("stage 3 (theirs) = %q, want to contain FROM_A", theirs)
	}
}

func TestConflictStage_AbsentAtStageReturnsNil(t *testing.T) {
	// secrets.enc has no common-ancestor version — it was created
	// independently by both diverged branches — so stage 1 (base) is
	// legitimately absent even though the file is actively conflicted.
	repo, path := makeDivergedMergeConflict(t)

	data, err := ConflictStage(repo, 1, path)
	if err != nil {
		t.Fatalf("ConflictStage for absent stage: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil bytes for absent stage, got %q", data)
	}
}

func TestStageFile_ResolvesConflict(t *testing.T) {
	repo, path := makeDivergedMergeConflict(t)

	// Resolve by keeping "ours" content, then stage it.
	ours, err := ConflictStage(repo, 2, path)
	if err != nil {
		t.Fatalf("ConflictStage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, path), ours, 0o600); err != nil {
		t.Fatalf("write resolved file: %v", err)
	}
	if err := StageFile(repo, path); err != nil {
		t.Fatalf("StageFile: %v", err)
	}

	remaining, err := ConflictedFiles(repo)
	if err != nil {
		t.Fatalf("ConflictedFiles: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no remaining conflicts after staging, got %v", remaining)
	}
}

func TestContinueMerge_CompletesAfterResolution(t *testing.T) {
	repo, path := makeDivergedMergeConflict(t)

	ours, err := ConflictStage(repo, 2, path)
	if err != nil {
		t.Fatalf("ConflictStage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, path), ours, 0o600); err != nil {
		t.Fatalf("write resolved file: %v", err)
	}
	if err := StageFile(repo, path); err != nil {
		t.Fatalf("StageFile: %v", err)
	}

	if err := ContinueMerge(repo); err != nil {
		t.Fatalf("ContinueMerge: %v", err)
	}

	// The merge should now be complete — no MERGE_HEAD left behind.
	if _, err := os.Stat(filepath.Join(repo, ".git", "MERGE_HEAD")); !os.IsNotExist(err) {
		t.Error("expected MERGE_HEAD to be gone after ContinueMerge")
	}
}

func TestAbortMerge_RestoresPreMergeState(t *testing.T) {
	repo, _ := makeDivergedMergeConflict(t)

	if err := AbortMerge(repo); err != nil {
		t.Fatalf("AbortMerge: %v", err)
	}

	if _, err := os.Stat(filepath.Join(repo, ".git", "MERGE_HEAD")); !os.IsNotExist(err) {
		t.Error("expected MERGE_HEAD to be gone after AbortMerge")
	}

	files, err := ConflictedFiles(repo)
	if err != nil {
		t.Fatalf("ConflictedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no conflicts after abort, got %v", files)
	}

	content, err := os.ReadFile(filepath.Join(repo, ".envault", "secrets.enc"))
	if err != nil {
		t.Fatalf("read secrets.enc after abort: %v", err)
	}
	if !strings.Contains(string(content), "FROM_B") {
		t.Errorf("expected pre-merge (FROM_B) content restored, got %q", content)
	}
}
