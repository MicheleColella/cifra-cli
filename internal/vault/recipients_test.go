package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// initVaultForTest creates a minimal vault directory with an empty recipients file.
func initVaultForTest(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if _, err := Init(root, "", false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return root
}

func TestListRecipients_EmptyFile(t *testing.T) {
	root := initVaultForTest(t)

	rs, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(rs) != 0 {
		t.Errorf("want 0 recipients, got %d", len(rs))
	}
}

func TestListRecipients_NoFile(t *testing.T) {
	root := t.TempDir() // no vault initialized

	rs, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients on missing file should not error: %v", err)
	}
	if rs != nil {
		t.Errorf("want nil, got %v", rs)
	}
}

func TestAddRecipient_And_List(t *testing.T) {
	root := initVaultForTest(t)

	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	r := Recipient{ID: "alice@example.com", PublicKey: pub}

	if err := AddRecipient(root, r); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	got, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 recipient, got %d", len(got))
	}
	if got[0].ID != r.ID {
		t.Errorf("ID = %q, want %q", got[0].ID, r.ID)
	}
	if got[0].PublicKey != r.PublicKey {
		t.Errorf("PublicKey mismatch")
	}
}

func TestAddRecipient_MultipleRecipients(t *testing.T) {
	root := initVaultForTest(t)

	for i, id := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		var pub [32]byte
		pub[0] = byte(i + 1)
		if err := AddRecipient(root, Recipient{ID: id, PublicKey: pub}); err != nil {
			t.Fatalf("AddRecipient(%s): %v", id, err)
		}
	}

	got, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("want 3 recipients, got %d", len(got))
	}
	if got[0].ID != "alice@example.com" || got[1].ID != "bob@example.com" || got[2].ID != "carol@example.com" {
		t.Errorf("unexpected order or IDs: %v", got)
	}
}

func TestAddRecipient_DuplicateID(t *testing.T) {
	root := initVaultForTest(t)

	var pub [32]byte
	r := Recipient{ID: "alice@example.com", PublicKey: pub}

	if err := AddRecipient(root, r); err != nil {
		t.Fatalf("first AddRecipient: %v", err)
	}
	err := AddRecipient(root, r)
	if err == nil {
		t.Fatal("expected error for duplicate ID")
	}
	if !errors.Is(err, ErrRecipientAlreadyExists) {
		t.Errorf("error = %v, want ErrRecipientAlreadyExists", err)
	}
}

func TestAddRecipient_NoVaultDir(t *testing.T) {
	root := t.TempDir() // no .cifra dir

	var pub [32]byte
	err := AddRecipient(root, Recipient{ID: "alice@example.com", PublicKey: pub})
	if err == nil {
		t.Fatal("expected error when vault not initialized")
	}
}

func TestParseRecipientLine_Valid(t *testing.T) {
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	line := "alice@example.com 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	r, err := ParseRecipientLine(line)
	if err != nil {
		t.Fatalf("ParseRecipientLine: %v", err)
	}
	if r.ID != "alice@example.com" {
		t.Errorf("ID = %q, want %q", r.ID, "alice@example.com")
	}
	if r.PublicKey != pub {
		t.Errorf("PublicKey mismatch: got %x, want %x", r.PublicKey, pub)
	}
}

func TestParseRecipientLine_InvalidHex(t *testing.T) {
	_, err := ParseRecipientLine("alice@example.com ZZZZ")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestParseRecipientLine_WrongByteCount(t *testing.T) {
	_, err := ParseRecipientLine("alice@example.com deadbeef") // only 4 bytes
	if err == nil {
		t.Fatal("expected error for wrong byte count")
	}
}

func TestParseRecipientLine_TooFewFields(t *testing.T) {
	_, err := ParseRecipientLine("alice@example.com")
	if err == nil {
		t.Fatal("expected error for missing pubkey field")
	}
}

func TestParseRecipientLine_TooManyFields(t *testing.T) {
	_, err := ParseRecipientLine("alice@example.com abc def")
	if err == nil {
		t.Fatal("expected error for extra fields")
	}
}

func TestRemoveRecipient_Removes(t *testing.T) {
	root := initVaultForTest(t)

	ids := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	for i, id := range ids {
		var pub [32]byte
		pub[0] = byte(i + 1)
		if err := AddRecipient(root, Recipient{ID: id, PublicKey: pub}); err != nil {
			t.Fatalf("AddRecipient(%s): %v", id, err)
		}
	}

	if err := RemoveRecipient(root, "bob@example.com"); err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}

	got, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 recipients after removal, got %d", len(got))
	}
	for _, r := range got {
		if r.ID == "bob@example.com" {
			t.Error("bob should have been removed")
		}
	}
}

func TestRemoveRecipient_NotFound(t *testing.T) {
	root := initVaultForTest(t)

	err := RemoveRecipient(root, "nobody@example.com")
	if err == nil {
		t.Fatal("expected error for non-existent recipient")
	}
	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("error = %v, want ErrRecipientNotFound", err)
	}
}

func TestRemoveRecipient_LastEntry(t *testing.T) {
	root := initVaultForTest(t)

	var pub [32]byte
	if err := AddRecipient(root, Recipient{ID: "alice@example.com", PublicKey: pub}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	if err := RemoveRecipient(root, "alice@example.com"); err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}

	got, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 recipients, got %d", len(got))
	}
}

func TestRemoveRecipient_Idempotent(t *testing.T) {
	root := initVaultForTest(t)

	var pub [32]byte
	_ = AddRecipient(root, Recipient{ID: "alice@example.com", PublicKey: pub})
	_ = RemoveRecipient(root, "alice@example.com")

	// Second removal must return ErrRecipientNotFound, not corrupt the file.
	err := RemoveRecipient(root, "alice@example.com")
	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("second removal: got %v, want ErrRecipientNotFound", err)
	}
}

func TestListRecipients_SkipsComments(t *testing.T) {
	root := initVaultForTest(t)

	// Write a file with a comment line manually.
	path := filepath.Join(root, DirName, recipientsFile)
	content := "# this is a comment\nalice@example.com 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	got, err := ListRecipients(root)
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want 1 recipient (comment skipped), got %d", len(got))
	}
}
