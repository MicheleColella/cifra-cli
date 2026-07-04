package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// hasConflictMarkers reports whether data contains a git text-merge conflict
// marker at the start of a line (`<<<<<<< `, `=======`, `>>>>>>> `). Checked
// line-anchored so legitimate base64 ciphertext containing these bytes mid-line
// never trips it.
func hasConflictMarkers(data []byte) bool {
	for _, marker := range [][]byte{[]byte("<<<<<<< "), []byte(">>>>>>> "), []byte("=======\n")} {
		if bytes.HasPrefix(data, marker) || bytes.Contains(data, append([]byte("\n"), marker...)) {
			return true
		}
	}
	return false
}

// MergeConflict describes an entry-level conflict that could not be auto-resolved.
// The caller must surface this to the user and abort the merge.
type MergeConflict struct {
	Name   string
	Kind   EntryKind
	Reason string
}

// MergeWarning describes an auto-resolved change that should be surfaced to the
// user — most commonly a recipient losing access on one side of the merge.
type MergeWarning struct {
	Name    string
	Kind    EntryKind
	Message string
}

// entryKey is the unique identity of a vault entry.
type entryKey struct {
	Name string
	Kind EntryKind
}

// ErrConflictMarkers is returned by ParseStore when secrets.enc contains git
// text-merge conflict markers — the corruption that happens when git text-merges
// the JSON store because the `cifra` merge driver was not registered (a teammate
// merged before running `cifra init --upgrade`). Actionable, never silent.
var ErrConflictMarkers = fmt.Errorf("secrets.enc contains git conflict markers — it was text-merged without the cifra merge driver; run `cifra init --upgrade`, then re-resolve (e.g. `cifra pull`)")

// ParseStore decodes a JSON-encoded secrets store from raw bytes.
// Returns an error if the bytes are not valid JSON or the version is unsupported.
func ParseStore(data []byte) (*Store, error) {
	if hasConflictMarkers(data) {
		return nil, ErrConflictMarkers
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse secrets store: %w", err)
	}
	if s.Version != storeVersion {
		return nil, fmt.Errorf("unsupported secrets store version %d", s.Version)
	}
	return &s, nil
}

// MergeStores performs a secret-level 3-way merge of base, ours, and theirs.
// Entry identity is (Name, Kind); equality is determined by UpdatedAt timestamp.
//
// Merge rules:
//   - Only ours added → keep ours
//   - Only theirs added → keep theirs
//   - Both added, same UpdatedAt → keep (idempotent)
//   - Both added, different → conflict
//   - Only ours changed → keep ours; warn if recipient dropped
//   - Only theirs changed → keep theirs; warn if recipient dropped
//   - Both changed to same UpdatedAt → keep
//   - Both changed differently → conflict
//   - Ours unchanged, theirs deleted → delete
//   - Theirs unchanged, ours deleted → delete
//   - Both deleted → delete
//   - Ours modified, theirs deleted → conflict
//   - Theirs modified, ours deleted → conflict
//
// If len(conflicts) > 0, the caller must abort the merge.
func MergeStores(base, ours, theirs *Store) (*Store, []MergeWarning, []MergeConflict) {
	bIdx := indexStore(base)
	oIdx := indexStore(ours)
	tIdx := indexStore(theirs)

	// Collect all unique keys, sort for deterministic output.
	keySet := make(map[entryKey]struct{}, len(bIdx)+len(oIdx)+len(tIdx))
	for k := range bIdx {
		keySet[k] = struct{}{}
	}
	for k := range oIdx {
		keySet[k] = struct{}{}
	}
	for k := range tIdx {
		keySet[k] = struct{}{}
	}
	keys := make([]entryKey, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Kind != keys[j].Kind {
			return keys[i].Kind < keys[j].Kind
		}
		return keys[i].Name < keys[j].Name
	})

	var entries []Entry
	var warnings []MergeWarning
	var conflicts []MergeConflict

	for _, k := range keys {
		b, bOK := bIdx[k]
		o, oOK := oIdx[k]
		t, tOK := tIdx[k]

		merged, w, c := mergeEntry(k, bOK, b, oOK, o, tOK, t)
		warnings = append(warnings, w...)
		conflicts = append(conflicts, c...)
		if merged != nil {
			entries = append(entries, *merged)
		}
	}

	return &Store{Version: storeVersion, Entries: entries}, warnings, conflicts
}

// mergeEntry applies the 3-way merge rules to a single entry.
func mergeEntry(k entryKey, bOK bool, b Entry, oOK bool, o Entry, tOK bool, t Entry) (*Entry, []MergeWarning, []MergeConflict) {
	switch {
	case !bOK && oOK && !tOK:
		return &o, nil, nil

	case !bOK && !oOK && tOK:
		return &t, nil, nil

	case !bOK && oOK && tOK:
		if sameEntry(o, t) {
			return &o, nil, nil
		}
		return nil, nil, []MergeConflict{{k.Name, k.Kind, "both sides added with different values"}}

	case bOK && !oOK && !tOK:
		return nil, nil, nil // both deleted

	case bOK && oOK && !tOK:
		if sameEntry(b, o) {
			return nil, nil, nil // ours unchanged, theirs deleted: respect deletion
		}
		return nil, nil, []MergeConflict{{k.Name, k.Kind, "ours modified but theirs deleted"}}

	case bOK && !oOK && tOK:
		if sameEntry(b, t) {
			return nil, nil, nil // theirs unchanged, ours deleted: respect deletion
		}
		return nil, nil, []MergeConflict{{k.Name, k.Kind, "theirs modified but ours deleted"}}

	case bOK && oOK && tOK:
		oChanged := !sameEntry(b, o)
		tChanged := !sameEntry(b, t)
		switch {
		case !oChanged && !tChanged:
			return &b, nil, nil
		case oChanged && !tChanged:
			w := recipientDropWarnings(k, b, o)
			return &o, w, nil
		case !oChanged && tChanged:
			w := recipientDropWarnings(k, b, t)
			return &t, w, nil
		default:
			if sameEntry(o, t) {
				return &o, nil, nil // identical change from both sides
			}
			return nil, nil, []MergeConflict{{k.Name, k.Kind, "both sides modified independently"}}
		}

	default:
		return nil, nil, nil // !bOK && !oOK && !tOK: unreachable
	}
}

// sameEntry reports whether a and b represent the same sealed version of an
// entry, determined by their UpdatedAt timestamps.
func sameEntry(a, b Entry) bool {
	return a.UpdatedAt.Equal(b.UpdatedAt)
}

// indexStore builds a (name, kind) → Entry lookup table from a store.
// A nil store is treated as an empty store.
func indexStore(s *Store) map[entryKey]Entry {
	if s == nil {
		return make(map[entryKey]Entry)
	}
	idx := make(map[entryKey]Entry, len(s.Entries))
	for _, e := range s.Entries {
		idx[entryKey{e.Name, e.Kind}] = e
	}
	return idx
}

// recipientDropWarnings returns a warning for each recipient present in before
// but absent in after (i.e., lost access as a result of this change).
func recipientDropWarnings(k entryKey, before, after Entry) []MergeWarning {
	beforeSet := make(map[string]struct{}, len(before.Recipients))
	for _, r := range before.Recipients {
		beforeSet[r] = struct{}{}
	}
	var warnings []MergeWarning
	for _, r := range after.Recipients {
		delete(beforeSet, r)
	}
	for dropped := range beforeSet {
		warnings = append(warnings, MergeWarning{
			Name:    k.Name,
			Kind:    k.Kind,
			Message: fmt.Sprintf("recipient %s lost access to %s", dropped, k.Name),
		})
	}
	return warnings
}
