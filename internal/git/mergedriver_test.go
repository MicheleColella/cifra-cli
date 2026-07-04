package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", args...) //nolint:gosec // test-only, hardcoded git args
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestRegisterMergeDriver_IdempotentAndDetectable(t *testing.T) {
	dir := initTestRepo(t)

	if IsMergeDriverRegistered(dir) {
		t.Fatal("driver should not be registered before RegisterMergeDriver")
	}
	if err := RegisterMergeDriver(dir); err != nil {
		t.Fatalf("RegisterMergeDriver: %v", err)
	}
	if !IsMergeDriverRegistered(dir) {
		t.Fatal("driver should be registered after RegisterMergeDriver")
	}

	// Idempotent + non-destructive: a second call must not clobber a user override.
	set := exec.Command("git", "config", "--local", "merge.cifra.driver", "custom %O %A %B")
	set.Dir = dir
	if out, err := set.CombinedOutput(); err != nil {
		t.Fatalf("set override: %v\n%s", err, out)
	}
	if err := RegisterMergeDriver(dir); err != nil {
		t.Fatalf("RegisterMergeDriver (2nd): %v", err)
	}
	got, _ := gitOutput(dir, "config", "--local", "--get", "merge.cifra.driver")
	if got == "" || got[:6] != "custom" {
		t.Errorf("existing driver override was clobbered, got %q", got)
	}
}

func TestEnsureGitAttributes_AppendsAndPreserves(t *testing.T) {
	dir := initTestRepo(t)
	attrs := filepath.Join(dir, ".gitattributes")

	// Pre-existing unrelated content must survive.
	if err := os.WriteFile(attrs, []byte("*.png binary\n"), 0o644); err != nil { //nolint:gosec // test .gitattributes fixture
		t.Fatal(err)
	}

	added, err := EnsureGitAttributes(dir)
	if err != nil || !added {
		t.Fatalf("EnsureGitAttributes: added=%v err=%v", added, err)
	}
	if !VaultDeclaresMergeDriver(dir) {
		t.Fatal("VaultDeclaresMergeDriver should be true after EnsureGitAttributes")
	}
	data, _ := os.ReadFile(attrs)
	if want := "*.png binary\n"; len(data) < len(want) || string(data[:len(want)]) != want {
		t.Errorf("existing .gitattributes content not preserved: %q", data)
	}

	// Second call is a no-op (does not duplicate the line).
	added2, err := EnsureGitAttributes(dir)
	if err != nil || added2 {
		t.Fatalf("second EnsureGitAttributes should be no-op: added=%v err=%v", added2, err)
	}
}

func TestMergeDriverMisconfigured(t *testing.T) {
	dir := initTestRepo(t)

	// Neither declared nor registered → not misconfigured (nothing routes to it).
	if MergeDriverMisconfigured(dir) {
		t.Error("clean repo should not be misconfigured")
	}

	// Declared in .gitattributes but NOT registered in .git/config → the danger state.
	if _, err := EnsureGitAttributes(dir); err != nil {
		t.Fatal(err)
	}
	if !MergeDriverMisconfigured(dir) {
		t.Error("declared-but-unregistered must report misconfigured")
	}

	// Register it → resolved.
	if err := RegisterMergeDriver(dir); err != nil {
		t.Fatal(err)
	}
	if MergeDriverMisconfigured(dir) {
		t.Error("registered driver must clear the misconfigured state")
	}
}
