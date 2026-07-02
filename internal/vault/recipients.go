package vault

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrRecipientAlreadyExists is returned by AddRecipient when an entry with the
// same ID is already present in the recipients file.
var ErrRecipientAlreadyExists = errors.New("recipient already exists for this id")

// ErrRecipientNotFound is returned by RemoveRecipient when no entry matches the given ID.
var ErrRecipientNotFound = errors.New("recipient not found")

// Recipient is a vault member identified by an ID and their X25519 public key.
type Recipient struct {
	ID        string
	PublicKey [32]byte
}

// AddRecipient appends r to the recipients file inside repoRoot.
// Returns ErrRecipientAlreadyExists if an entry with the same ID is already present.
func AddRecipient(repoRoot string, r Recipient) (err error) {
	existing, err := ListRecipients(repoRoot)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.ID == r.ID {
			return fmt.Errorf("%w: %s", ErrRecipientAlreadyExists, r.ID)
		}
	}

	path := filepath.Join(repoRoot, DirName, recipientsFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open recipients file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close recipients file: %w", cerr)
		}
	}()

	line := fmt.Sprintf("%s %s\n", r.ID, hex.EncodeToString(r.PublicKey[:]))
	if _, err := fmt.Fprint(f, line); err != nil {
		return fmt.Errorf("write recipient: %w", err)
	}
	return nil
}

// ListRecipients reads all recipients from the recipients file inside repoRoot.
// Returns an empty slice (not an error) when the file does not exist.
func ListRecipients(repoRoot string) ([]Recipient, error) {
	path := filepath.Join(repoRoot, DirName, recipientsFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open recipients file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []Recipient
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := ParseRecipientLine(line)
		if err != nil {
			return nil, fmt.Errorf("recipients line %d: %w", lineNum, err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan recipients: %w", err)
	}
	return out, nil
}

// RemoveRecipient removes the entry with the given id from the recipients file.
// Returns ErrRecipientNotFound if no entry matches.
func RemoveRecipient(repoRoot, id string) error {
	existing, err := ListRecipients(repoRoot)
	if err != nil {
		return err
	}

	found := false
	kept := existing[:0:0] // same backing type but zero len/cap copy
	for _, r := range existing {
		if r.ID == id {
			found = true
		} else {
			kept = append(kept, r)
		}
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrRecipientNotFound, id)
	}

	return writeRecipients(repoRoot, kept)
}

// writeRecipients atomically replaces the recipients file with the given slice.
func writeRecipients(repoRoot string, recipients []Recipient) error {
	path := filepath.Join(repoRoot, DirName, recipientsFile)
	tmpPath := path + ".tmp"

	var buf strings.Builder
	for _, r := range recipients {
		_, _ = fmt.Fprintf(&buf, "%s %s\n", r.ID, hex.EncodeToString(r.PublicKey[:]))
	}

	if err := os.WriteFile(tmpPath, []byte(buf.String()), 0o600); err != nil {
		return fmt.Errorf("write recipients temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace recipients file: %w", err)
	}
	return nil
}

// ParseRecipientLine parses a "<id> <hex-pubkey>" string as written by AddRecipient
// and produced by "cifra key export --public".
func ParseRecipientLine(line string) (Recipient, error) {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return Recipient{}, fmt.Errorf("expected \"<id> <hex-pubkey>\", got %q", line)
	}
	id, hexKey := parts[0], parts[1]

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return Recipient{}, fmt.Errorf("invalid hex pubkey: %w", err)
	}
	if len(keyBytes) != 32 {
		return Recipient{}, fmt.Errorf("pubkey must be 32 bytes, got %d", len(keyBytes))
	}

	var pub [32]byte
	copy(pub[:], keyBytes)
	return Recipient{ID: id, PublicKey: pub}, nil
}
