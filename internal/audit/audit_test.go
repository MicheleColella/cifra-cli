package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func makeVaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAppendEntry_CreatesLog(t *testing.T) {
	dir := makeVaultDir(t)
	if err := AppendEntry(dir, "Read", ActionBlockedPath, "config/secrets.json", "config/secrets.json"); err != nil {
		t.Fatalf("AppendEntry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cifra", logFile)); err != nil {
		t.Fatalf("log not created: %v", err)
	}
}

func TestAppendEntry_MultipleEntries(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Bash", ActionBlockedCmd, "cat secrets.json", "secrets.json")
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "data/customers.csv", "data/")
	_ = AppendEntry(dir, "Bash", ActionMasked, "DB_PASSWORD", "")

	entries, err := LoadEntries(dir)
	if err != nil {
		t.Fatalf("LoadEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestVerifyChain_ValidChain(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "a.json", "a.json")
	_ = AppendEntry(dir, "Bash", ActionBlockedCmd, "cat a.json", "a.json")
	_ = AppendEntry(dir, "Bash", ActionMasked, "SECRET", "")

	entries, _ := LoadEntries(dir)
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChain_EmptyChain(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Errorf("empty chain should verify ok: %v", err)
	}
}

func TestVerifyChain_DetectsTamperedHash(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "secret.json", "secret.json")

	entries, _ := LoadEntries(dir)
	entries[0].Hash = "deadbeef" // tamper with the hash

	if err := VerifyChain(entries); err == nil {
		t.Error("expected chain verification to fail after hash tamper")
	}
}

func TestVerifyChain_DetectsBrokenChain(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "a.json", "a.json")
	_ = AppendEntry(dir, "Bash", ActionBlockedCmd, "cat a.json", "a.json")

	entries, _ := LoadEntries(dir)
	// Corrupt the Prev pointer of the second entry.
	entries[1].Prev = "wronghash"
	entries[1].Hash = computeHash(entries[1]) // re-sign with wrong prev

	if err := VerifyChain(entries); err == nil {
		t.Error("expected chain verification to fail after broken chain link")
	}
}

func TestLoadEntries_NilWhenAbsent(t *testing.T) {
	dir := makeVaultDir(t)
	entries, err := LoadEntries(dir)
	if err != nil {
		t.Fatalf("LoadEntries on empty dir: %v", err)
	}
	if entries != nil {
		t.Error("expected nil entries when log absent")
	}
}

func TestAppendEntry_FirstEntryHasEmptyPrev(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "file.json", "file.json")
	entries, _ := LoadEntries(dir)
	if entries[0].Prev != "" {
		t.Errorf("first entry should have empty Prev, got %q", entries[0].Prev)
	}
}

func TestAppendEntry_ChainLinkageCorrect(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AppendEntry(dir, "Read", ActionBlockedPath, "a.json", "a.json")
	_ = AppendEntry(dir, "Bash", ActionBlockedCmd, "cat b.json", "b.json")

	entries, _ := LoadEntries(dir)
	if entries[1].Prev != entries[0].Hash {
		t.Errorf("second entry Prev=%q does not match first entry Hash=%q", entries[1].Prev, entries[0].Hash)
	}
}
