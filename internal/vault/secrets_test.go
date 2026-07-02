package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	envcrypto "github.com/MicheleColella/envault-cli/internal/crypto"
)

// writeRawStore drops a hand-crafted secrets.enc into an initialized vault so a
// test can exercise LoadStore against a specific on-disk schema version.
func writeRawStore(t *testing.T, root, json string) {
	t.Helper()
	if _, err := Init(root, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	path := filepath.Join(root, DirName, secretsFile)
	if err := os.WriteFile(path, []byte(json), 0o600); err != nil {
		t.Fatalf("write raw store: %v", err)
	}
}

// TestLoadStore_NewerVersionRejectedClearly is the forward-compatibility guard:
// a store written by a NEWER envault must fail with an actionable "upgrade"
// message, never be parsed as if it were the current schema.
func TestLoadStore_NewerVersionRejectedClearly(t *testing.T) {
	root := t.TempDir()
	writeRawStore(t, root, `{"version":99,"entries":[]}`)

	_, err := LoadStore(root)
	if err == nil {
		t.Fatal("expected error loading a newer-version store, got nil")
	}
	if !strings.Contains(err.Error(), "upgrade envault") {
		t.Errorf("error should tell the user to upgrade, got %q", err.Error())
	}
}

// TestLoadStore_OlderUnsupportedVersionRejected ensures an out-of-range older
// schema is rejected (and is the extension point for future migrations).
func TestLoadStore_OlderUnsupportedVersionRejected(t *testing.T) {
	root := t.TempDir()
	writeRawStore(t, root, `{"version":0,"entries":[]}`)

	if _, err := LoadStore(root); err == nil {
		t.Fatal("expected error loading an unsupported older-version store, got nil")
	}
}

// TestLoadStore_CurrentVersionLoads confirms the current schema still loads.
func TestLoadStore_CurrentVersionLoads(t *testing.T) {
	root := t.TempDir()
	writeRawStore(t, root, `{"version":1,"entries":[]}`)

	if _, err := LoadStore(root); err != nil {
		t.Fatalf("current-version store should load, got %v", err)
	}
}

func sealTestEntry(t *testing.T, name string, kind EntryKind, payload string) Entry {
	t.Helper()
	_, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	env, err := envcrypto.Seal([]byte(payload), []envcrypto.PublicKey{pub}, envcrypto.AES256GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	now := time.Now().UTC()
	return Entry{
		Name:       name,
		Kind:       kind,
		Algorithm:  envcrypto.AES256GCM,
		Recipients: []string{"alice@example.com"},
		CreatedAt:  now,
		UpdatedAt:  now,
		Envelope:   env,
	}
}

func TestLoadStore_MissingReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	s, err := LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(s.Entries) != 0 {
		t.Errorf("expected empty store, got %d entries", len(s.Entries))
	}
}

// TestSaveStore_CrashBeforeRenameLeavesVaultIntact simulates a power loss that
// happens after the temp file is written and fsynced, but before the rename
// that publishes it. Since SaveStore never writes secrets.enc directly, the
// previous store must still load correctly, and an interrupted temp file next
// to it must never confuse LoadStore.
func TestSaveStore_CrashBeforeRenameLeavesVaultIntact(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	original := (&Store{}).Upsert(sealTestEntry(t, "ORIGINAL", KindEnv, "before-crash"))
	if err := SaveStore(root, original); err != nil {
		t.Fatalf("SaveStore(original): %v", err)
	}

	// Replicate SaveStore's write+fsync step directly against the same tmpPath
	// convention, without ever calling the rename that publishes it — this is
	// the state a crash right before rename would leave on disk.
	path := filepath.Join(root, DirName, secretsFile)
	tmpPath := path + ".tmp"
	pending := (&Store{}).Upsert(sealTestEntry(t, "NEVER_PUBLISHED", KindEnv, "in-flight"))
	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	loaded, err := LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore after simulated crash: %v", err)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].Name != "ORIGINAL" {
		t.Fatalf("vault corrupted by unpublished temp file: got %+v", loaded.Entries)
	}
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("expected leftover temp file to still exist on disk: %v", err)
	}
}

func TestSaveAndLoadStore_RoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	s, _ := LoadStore(root)
	s = s.Upsert(sealTestEntry(t, "API_KEY", KindEnv, "shh"))
	if err := SaveStore(root, s); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	loaded, err := LoadStore(root)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(loaded.Entries))
	}
	if loaded.Entries[0].Name != "API_KEY" || loaded.Entries[0].Kind != KindEnv {
		t.Errorf("round-tripped entry = %+v", loaded.Entries[0])
	}
	if loaded.Entries[0].Algorithm != envcrypto.AES256GCM {
		t.Errorf("algorithm = %q, want aes-256-gcm", loaded.Entries[0].Algorithm)
	}
}

func TestUpsert_DoesNotMutateReceiver(t *testing.T) {
	original := &Store{Version: storeVersion}
	original.Upsert(sealTestEntry(t, "X", KindEnv, "v"))
	if len(original.Entries) != 0 {
		t.Errorf("Upsert mutated the receiver: %d entries", len(original.Entries))
	}
}

func TestUpsert_ReplacesSameNameAndKind(t *testing.T) {
	s := &Store{Version: storeVersion}
	s = s.Upsert(sealTestEntry(t, "TOKEN", KindEnv, "old"))
	s = s.Upsert(sealTestEntry(t, "TOKEN", KindEnv, "new"))

	if len(s.Entries) != 1 {
		t.Fatalf("expected replacement, got %d entries", len(s.Entries))
	}
}

func TestUpsert_SameNameDifferentKindCoexist(t *testing.T) {
	s := &Store{Version: storeVersion}
	s = s.Upsert(sealTestEntry(t, "config", KindEnv, "a"))
	s = s.Upsert(sealTestEntry(t, "config", KindFile, "b"))

	if len(s.Entries) != 2 {
		t.Errorf("expected env and file entries to coexist, got %d", len(s.Entries))
	}
}

func TestDelete_RemovesMatchingEntry(t *testing.T) {
	s := &Store{Version: storeVersion}
	s = s.Upsert(sealTestEntry(t, "TOKEN", KindEnv, "v"))
	s = s.Delete("TOKEN", KindEnv)

	if len(s.Entries) != 0 {
		t.Errorf("expected 0 entries after Delete, got %d", len(s.Entries))
	}
}

func TestDelete_DoesNotMutateReceiver(t *testing.T) {
	original := &Store{Version: storeVersion}
	original = original.Upsert(sealTestEntry(t, "X", KindEnv, "v"))
	original.Delete("X", KindEnv)
	if len(original.Entries) != 1 {
		t.Errorf("Delete mutated the receiver: %d entries", len(original.Entries))
	}
}

func TestDelete_NoopWhenNotFound(t *testing.T) {
	s := &Store{Version: storeVersion}
	s = s.Upsert(sealTestEntry(t, "TOKEN", KindEnv, "v"))
	s2 := s.Delete("MISSING", KindEnv)

	if len(s2.Entries) != 1 {
		t.Errorf("expected store unchanged, got %d entries", len(s2.Entries))
	}
}

func TestDelete_OnlyRemovesMatchingKind(t *testing.T) {
	s := &Store{Version: storeVersion}
	s = s.Upsert(sealTestEntry(t, "config", KindEnv, "env-val"))
	s = s.Upsert(sealTestEntry(t, "config", KindFile, "file-val"))
	s = s.Delete("config", KindEnv)

	if len(s.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(s.Entries))
	}
	if s.Entries[0].Kind != KindFile {
		t.Errorf("wrong entry remaining: kind = %q, want file", s.Entries[0].Kind)
	}
}

func TestUpsert_PreservesCreatedAtOnReplace(t *testing.T) {
	s := &Store{Version: storeVersion}
	first := sealTestEntry(t, "TOKEN", KindEnv, "old")
	first.CreatedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s = s.Upsert(first)

	second := sealTestEntry(t, "TOKEN", KindEnv, "new")
	second.CreatedAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	second.UpdatedAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s = s.Upsert(second)

	got := s.Entries[0]
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt = %v, want preserved %v", got.CreatedAt, first.CreatedAt)
	}
	if !got.UpdatedAt.Equal(second.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, second.UpdatedAt)
	}
}
