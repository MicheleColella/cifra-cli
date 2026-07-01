package vault

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// makeEntry builds a minimal Entry with the given name and UpdatedAt offset.
func makeEntry(name string, kind EntryKind, recipients []string, offsetSec int) Entry {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return Entry{
		Name:       name,
		Kind:       kind,
		Recipients: recipients,
		UpdatedAt:  base.Add(time.Duration(offsetSec) * time.Second),
		CreatedAt:  base,
	}
}

// findEntry returns the named entry in the store, or nil.
func findEntryIn(s *Store, name string) *Entry {
	for i := range s.Entries {
		if s.Entries[i].Name == name {
			return &s.Entries[i]
		}
	}
	return nil
}

func TestMergeStores_OnlyOursAdded(t *testing.T) {
	base := makeStore(nil)
	ours := makeStore([]Entry{makeEntry("KEY", KindEnv, nil, 10)})
	theirs := makeStore(nil)

	merged, warnings, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if findEntryIn(merged, "KEY") == nil {
		t.Error("merged store missing 'KEY' added only in ours")
	}
}

func TestMergeStores_OnlyTheirsAdded(t *testing.T) {
	base := makeStore(nil)
	ours := makeStore(nil)
	theirs := makeStore([]Entry{makeEntry("SECRET", KindEnv, nil, 5)})

	merged, warnings, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if findEntryIn(merged, "SECRET") == nil {
		t.Error("merged store missing 'SECRET' added only in theirs")
	}
}

func TestMergeStores_BothAddedSame(t *testing.T) {
	e := makeEntry("TOKEN", KindEnv, nil, 20)
	base := makeStore(nil)
	ours := makeStore([]Entry{e})
	theirs := makeStore([]Entry{e})

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if findEntryIn(merged, "TOKEN") == nil {
		t.Error("merged missing idempotently added 'TOKEN'")
	}
}

func TestMergeStores_BothAddedDifferent(t *testing.T) {
	base := makeStore(nil)
	ours := makeStore([]Entry{makeEntry("KEY", KindEnv, nil, 10)})
	theirs := makeStore([]Entry{makeEntry("KEY", KindEnv, nil, 20)}) // different UpdatedAt

	_, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(conflicts), conflicts)
	}
	if conflicts[0].Name != "KEY" {
		t.Errorf("conflict name = %q, want %q", conflicts[0].Name, "KEY")
	}
}

func TestMergeStores_OnlyOursModified(t *testing.T) {
	orig := makeEntry("DB", KindEnv, nil, 0)
	modified := makeEntry("DB", KindEnv, nil, 30)

	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{modified})
	theirs := makeStore([]Entry{orig})

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if e := findEntryIn(merged, "DB"); e == nil {
		t.Fatal("merged missing 'DB'")
	} else if !e.UpdatedAt.Equal(modified.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v (ours modified)", e.UpdatedAt, modified.UpdatedAt)
	}
}

func TestMergeStores_OnlyTheirsModified(t *testing.T) {
	orig := makeEntry("API", KindEnv, nil, 0)
	modified := makeEntry("API", KindEnv, nil, 40)

	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{orig})
	theirs := makeStore([]Entry{modified})

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if e := findEntryIn(merged, "API"); e == nil {
		t.Fatal("merged missing 'API'")
	} else if !e.UpdatedAt.Equal(modified.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v (theirs modified)", e.UpdatedAt, modified.UpdatedAt)
	}
}

func TestMergeStores_BothModifiedSame(t *testing.T) {
	orig := makeEntry("PASS", KindEnv, nil, 0)
	both := makeEntry("PASS", KindEnv, nil, 50)

	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{both})
	theirs := makeStore([]Entry{both})

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if findEntryIn(merged, "PASS") == nil {
		t.Error("merged missing 'PASS' with identical change on both sides")
	}
}

func TestMergeStores_BothModifiedDifferently(t *testing.T) {
	orig := makeEntry("CRED", KindEnv, nil, 0)

	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{makeEntry("CRED", KindEnv, nil, 10)})
	theirs := makeStore([]Entry{makeEntry("CRED", KindEnv, nil, 20)})

	_, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].Name != "CRED" {
		t.Errorf("conflict name = %q, want %q", conflicts[0].Name, "CRED")
	}
}

func TestMergeStores_OursDeletedUnchanged(t *testing.T) {
	orig := makeEntry("OLD", KindEnv, nil, 0)
	base := makeStore([]Entry{orig})
	ours := makeStore(nil)             // deleted
	theirs := makeStore([]Entry{orig}) // unchanged

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if findEntryIn(merged, "OLD") != nil {
		t.Error("entry deleted in ours should be absent from merge result")
	}
}

func TestMergeStores_TheirsDeletedUnchanged(t *testing.T) {
	orig := makeEntry("GONE", KindEnv, nil, 0)
	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{orig}) // unchanged
	theirs := makeStore(nil)         // deleted

	merged, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if findEntryIn(merged, "GONE") != nil {
		t.Error("entry deleted in theirs should be absent from merge result")
	}
}

func TestMergeStores_OursModifiedTheirsDeleted(t *testing.T) {
	orig := makeEntry("KEY", KindEnv, nil, 0)
	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{makeEntry("KEY", KindEnv, nil, 5)}) // modified
	theirs := makeStore(nil)                                      // deleted

	_, _, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
}

func TestMergeStores_RecipientDropWarning(t *testing.T) {
	orig := makeEntry("SEC", KindEnv, []string{"alice", "bob"}, 0)
	dropped := makeEntry("SEC", KindEnv, []string{"alice"}, 10) // bob removed

	base := makeStore([]Entry{orig})
	ours := makeStore([]Entry{dropped}) // ours removed bob
	theirs := makeStore([]Entry{orig})  // theirs unchanged

	_, warnings, conflicts := MergeStores(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning about recipient drop, got none")
	}
	found := false
	for _, w := range warnings {
		if w.Name == "SEC" && contains(w.Message, "bob") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning mentioning 'bob' for SEC, got: %v", warnings)
	}
}

func TestMergeStores_NilBase(t *testing.T) {
	// Simulate a file newly created on both sides (no common ancestor).
	e := makeEntry("NEW", KindEnv, nil, 5)
	ours := makeStore([]Entry{e})
	theirs := makeStore([]Entry{e}) // same entry

	merged, _, conflicts := MergeStores(nil, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if findEntryIn(merged, "NEW") == nil {
		t.Error("merged missing 'NEW' added identically on both sides")
	}
}

func TestParseStore_Valid(t *testing.T) {
	s := &Store{Version: 1, Entries: []Entry{
		{Name: "K", Kind: KindEnv},
	}}
	data, _ := json.Marshal(s)

	parsed, err := ParseStore(data)
	if err != nil {
		t.Fatalf("ParseStore: %v", err)
	}
	if len(parsed.Entries) != 1 || parsed.Entries[0].Name != "K" {
		t.Errorf("unexpected parsed store: %+v", parsed)
	}
}

func TestParseStore_InvalidJSON(t *testing.T) {
	_, err := ParseStore([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseStore_WrongVersion(t *testing.T) {
	s := &Store{Version: 99}
	data, _ := json.Marshal(s)
	_, err := ParseStore(data)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
