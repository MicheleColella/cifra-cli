package protect

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

func TestAddPattern_AddsEntry(t *testing.T) {
	dir := makeVaultDir(t)
	if err := AddPattern(dir, "config/secrets.json"); err != nil {
		t.Fatalf("AddPattern: %v", err)
	}
	patterns, _ := LoadPatterns(dir)
	if len(patterns) != 1 || patterns[0] != "config/secrets.json" {
		t.Errorf("unexpected patterns: %v", patterns)
	}
}

func TestAddPattern_Idempotent(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AddPattern(dir, "config/secrets.json")
	_ = AddPattern(dir, "config/secrets.json")
	patterns, _ := LoadPatterns(dir)
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern after double add, got %d", len(patterns))
	}
}

func TestRemovePattern_RemovesEntry(t *testing.T) {
	dir := makeVaultDir(t)
	_ = AddPattern(dir, "config/secrets.json")
	if err := RemovePattern(dir, "config/secrets.json"); err != nil {
		t.Fatalf("RemovePattern: %v", err)
	}
	patterns, _ := LoadPatterns(dir)
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns after remove, got %v", patterns)
	}
}

func TestRemovePattern_ErrWhenNotFound(t *testing.T) {
	dir := makeVaultDir(t)
	if err := RemovePattern(dir, "nonexistent"); err != ErrPatternNotFound {
		t.Errorf("expected ErrPatternNotFound, got %v", err)
	}
}

func TestLoadPatterns_EmptyWhenFileAbsent(t *testing.T) {
	dir := makeVaultDir(t)
	patterns, err := LoadPatterns(dir)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected empty, got %v", patterns)
	}
}

func TestMatchesAny_ExactPath(t *testing.T) {
	patterns := []string{"config/secrets.json"}
	p, ok := MatchesAny("config/secrets.json", patterns)
	if !ok || p != "config/secrets.json" {
		t.Errorf("expected match, got ok=%v p=%q", ok, p)
	}
}

func TestMatchesAny_GlobPattern(t *testing.T) {
	patterns := []string{"config/*.json"}
	p, ok := MatchesAny("config/pricing.json", patterns)
	if !ok || p != "config/*.json" {
		t.Errorf("expected glob match, got ok=%v p=%q", ok, p)
	}
}

func TestMatchesAny_BasenameMatch(t *testing.T) {
	patterns := []string{"secrets.json"}
	p, ok := MatchesAny("some/deep/path/secrets.json", patterns)
	if !ok || p != "secrets.json" {
		t.Errorf("expected basename match, got ok=%v p=%q", ok, p)
	}
}

func TestMatchesAny_DirectoryPrefix(t *testing.T) {
	patterns := []string{"config/"}
	_, ok := MatchesAny("config/nested/secrets.json", patterns)
	if !ok {
		t.Error("expected directory prefix match")
	}
}

func TestMatchesAny_NoMatch(t *testing.T) {
	patterns := []string{"config/secrets.json"}
	_, ok := MatchesAny("other/file.txt", patterns)
	if ok {
		t.Error("expected no match")
	}
}

func TestMatchesAny_EmptyPatterns(t *testing.T) {
	_, ok := MatchesAny("any/path.txt", []string{})
	if ok {
		t.Error("expected no match with empty patterns")
	}
}

func TestContainsProtectedPath_FindsPathInCommand(t *testing.T) {
	patterns := []string{"config/secrets.json"}
	p, tok, ok := ContainsProtectedPath("cat config/secrets.json", patterns)
	if !ok {
		t.Error("expected protected path found in command")
	}
	if p != "config/secrets.json" {
		t.Errorf("unexpected pattern %q", p)
	}
	if tok != "config/secrets.json" {
		t.Errorf("unexpected token %q", tok)
	}
}

func TestContainsProtectedPath_NoMatchWhenPathAbsent(t *testing.T) {
	patterns := []string{"config/secrets.json"}
	_, _, ok := ContainsProtectedPath("ls -la", patterns)
	if ok {
		t.Error("unexpected match")
	}
}

func TestContainsProtectedPath_MatchesGlobInBash(t *testing.T) {
	patterns := []string{"data/*.csv"}
	_, _, ok := ContainsProtectedPath("python process.py data/customers.csv", patterns)
	if !ok {
		t.Error("expected glob match in bash command")
	}
}
