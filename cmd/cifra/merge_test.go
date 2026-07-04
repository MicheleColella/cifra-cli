package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func mergeEntry(name string, updated time.Time) vault.Entry {
	return vault.Entry{
		Name:      name,
		Kind:      vault.KindEnv,
		Algorithm: "AES256GCM",
		CreatedAt: time.Unix(0, 0).UTC(),
		UpdatedAt: updated.UTC(),
	}
}

// writeStoreFile writes a store to a temp file in the driver's on-disk format.
// A nil store writes an empty file (git's %O for an add/add merge).
func writeStoreFile(t *testing.T, dir, name string, s *vault.Store) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var data []byte
	if s != nil {
		b, err := vault.MarshalStore(s)
		if err != nil {
			t.Fatalf("MarshalStore: %v", err)
		}
		data = b
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunMerge_AutoMergesDisjointAdds(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(100, 0)
	base := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", t0)}}
	ours := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", t0), mergeEntry("B", t0)}}
	theirs := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", t0), mergeEntry("C", t0)}}

	basePath := writeStoreFile(t, dir, "base", base)
	oursPath := writeStoreFile(t, dir, "ours", ours)
	theirsPath := writeStoreFile(t, dir, "theirs", theirs)

	if err := runMerge(basePath, oursPath, theirsPath); err != nil {
		t.Fatalf("runMerge should auto-merge disjoint adds, got: %v", err)
	}

	// Driver writes the result to oursPath (%A).
	data, _ := os.ReadFile(oursPath)
	merged, err := vault.ParseStore(data)
	if err != nil {
		t.Fatalf("parse merged: %v", err)
	}
	names := map[string]bool{}
	for _, e := range merged.Entries {
		names[e.Name] = true
	}
	for _, want := range []string{"A", "B", "C"} {
		if !names[want] {
			t.Errorf("merged store missing %q: got %v", want, names)
		}
	}
}

func TestRunMerge_ConflictExitsNonzeroAndLeavesOurs(t *testing.T) {
	dir := t.TempDir()
	base := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", time.Unix(100, 0))}}
	ours := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", time.Unix(200, 0))}}
	theirs := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", time.Unix(300, 0))}}

	basePath := writeStoreFile(t, dir, "base", base)
	oursPath := writeStoreFile(t, dir, "ours", ours)
	theirsPath := writeStoreFile(t, dir, "theirs", theirs)

	before, _ := os.ReadFile(oursPath)
	err := runMerge(basePath, oursPath, theirsPath)
	if err == nil {
		t.Fatal("divergent edits to the same entry must conflict (nonzero exit)")
	}
	after, _ := os.ReadFile(oursPath)
	if string(before) != string(after) {
		t.Error("on conflict the driver must leave %A (ours) untouched for manual resolution")
	}
}

func TestRunMerge_EmptyBaseIsUnion(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(100, 0)
	ours := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("A", t0)}}
	theirs := &vault.Store{Version: 1, Entries: []vault.Entry{mergeEntry("B", t0)}}

	basePath := writeStoreFile(t, dir, "base", nil) // empty %O
	oursPath := writeStoreFile(t, dir, "ours", ours)
	theirsPath := writeStoreFile(t, dir, "theirs", theirs)

	if err := runMerge(basePath, oursPath, theirsPath); err != nil {
		t.Fatalf("runMerge with empty base: %v", err)
	}
	data, _ := os.ReadFile(oursPath)
	merged, _ := vault.ParseStore(data)
	if len(merged.Entries) != 2 {
		t.Errorf("expected union of 2 entries, got %d", len(merged.Entries))
	}
}
