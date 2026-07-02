package keychain

import (
	"bytes"
	"testing"
)

func TestReseal_LegacyKeyBecomesV2(t *testing.T) {
	inner := newMemStore()
	key := randomKey(t)
	if err := inner.Seal("alice@example.com", key); err != nil { // raw legacy write
		t.Fatalf("inner.Seal: %v", err)
	}

	if err := Reseal(inner, fixedPass("new-passphrase"), "alice@example.com"); err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	stored := inner.data["alice@example.com"]
	_, kind := classifyKeyBlob(stored)
	if kind != blobProtectedV2 {
		t.Fatalf("expected id to hold a v2 blob after reseal, got kind=%v", kind)
	}

	protected := NewProtected(inner, fixedPass("new-passphrase"))
	got, err := protected.Unseal("alice@example.com")
	if err != nil {
		t.Fatalf("Unseal after reseal: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("resealed key mismatch: got %x want %x", got, key)
	}
}

func TestReseal_ExistingV2KeyIsResealed(t *testing.T) {
	inner := newMemStore()
	key := randomKey(t)
	original := NewProtected(inner, fixedPass("old-passphrase"))
	if err := original.Seal("bob", key); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if err := Reseal(inner, fixedPass("old-passphrase"), "bob"); err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	got, err := original.Unseal("bob")
	if err != nil {
		t.Fatalf("Unseal after reseal: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("resealed key mismatch: got %x want %x", got, key)
	}
}

func TestReseal_NoTempIDLeftBehindOnSuccess(t *testing.T) {
	inner := newMemStore()
	key := randomKey(t)
	if err := inner.Seal("carol", key); err != nil {
		t.Fatalf("inner.Seal: %v", err)
	}

	if err := Reseal(inner, fixedPass("pw"), "carol"); err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	for id := range inner.data {
		if id != "carol" {
			t.Fatalf("unexpected leftover keychain entry: %q", id)
		}
	}
}

func TestReseal_MissingKeyErrors(t *testing.T) {
	inner := newMemStore()
	if err := Reseal(inner, fixedPass("pw"), "nobody"); err == nil {
		t.Fatal("expected error resealing a nonexistent id")
	}
	if len(inner.data) != 0 {
		t.Fatalf("expected no keychain entries created, got %v", inner.data)
	}
}

// failingSealStore wraps memStore so Seal fails once its threshold is hit —
// used to verify Reseal never leaves the original id keyless on failure.
type failingSealStore struct {
	*memStore
	sealsAllowed int
	seals        int
}

func (f *failingSealStore) Seal(id string, key []byte) error {
	f.seals++
	if f.seals > f.sealsAllowed {
		return errNotAvailableForTest
	}
	return f.memStore.Seal(id, key)
}

var errNotAvailableForTest = &sealFailure{}

type sealFailure struct{}

func (*sealFailure) Error() string { return "simulated keychain seal failure" }

func TestReseal_OriginalUntouchedWhenTempSealFails(t *testing.T) {
	inner := &failingSealStore{memStore: newMemStore(), sealsAllowed: 0}
	key := randomKey(t)
	if err := inner.memStore.Seal("dan", key); err != nil { // seed directly, bypassing the failing wrapper
		t.Fatalf("seed Seal: %v", err)
	}

	if err := Reseal(inner, fixedPass("pw"), "dan"); err == nil {
		t.Fatal("expected error when the temp-id Seal fails")
	}

	// Original entry must be untouched — Reseal must not have deleted it.
	got := inner.data["dan"]
	if !bytes.Equal(got, key) {
		t.Fatalf("original key was modified after a failed reseal: got %x want %x", got, key)
	}
	if len(inner.data) != 1 {
		t.Fatalf("expected only the original entry to remain, got %v", inner.data)
	}
}

func TestReseal_FinalSealFailureLeavesRecoverableTempCopy(t *testing.T) {
	// Allow exactly one Seal (the temp-id staging write) to succeed, then fail
	// the final Seal(id, ...) — this is the "delete succeeded, reseal failed"
	// case Reseal must never silently lose the key over.
	inner := &failingSealStore{memStore: newMemStore(), sealsAllowed: 1}
	key := randomKey(t)
	if err := inner.memStore.Seal("erin", key); err != nil {
		t.Fatalf("seed Seal: %v", err)
	}

	err := Reseal(inner, fixedPass("pw"), "erin")
	if err == nil {
		t.Fatal("expected error when the final Seal(id, ...) fails")
	}

	// id must not silently retain the OLD entry (it was deleted) — but a
	// verified working copy must still exist somewhere in the keychain.
	if _, ok := inner.data["erin"]; ok {
		t.Fatal("did not expect the old entry to still be present under the original id")
	}
	found := false
	for id, blob := range inner.data {
		if id == "erin" {
			continue
		}
		protected := NewProtected(inner.memStore, fixedPass("pw"))
		got, uerr := protected.Unseal(id)
		if uerr == nil && bytes.Equal(got, key) {
			found = true
		}
		_ = blob
	}
	if !found {
		t.Fatal("no recoverable verified copy of the key survives the failed final Seal")
	}
}
