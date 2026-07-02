package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const logFile = "ai-secure.log"

// Action constants for audit log entries.
const (
	ActionBlockedPath = "blocked_path" // file tool blocked due to protected path
	ActionBlockedCmd  = "blocked_cmd"  // Bash command blocked due to protected path
	ActionMasked      = "masked"       // secret value replaced with placeholder in tool output
)

// Entry is a single record in the audit log.
type Entry struct {
	Time    string `json:"t"`
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Target  string `json:"target"`  // file path, command snippet, or masked secret name
	Pattern string `json:"pattern"` // matched protect pattern (empty for masked entries)
	Prev    string `json:"prev"`    // hash of the immediately preceding entry
	Hash    string `json:"hash"`    // SHA256 of this entry (fields above, not hash itself)
}

// AppendEntry appends a new signed entry to .cifra/ai-secure.log.
// The entry's hash chains from the last entry in the log.
func AppendEntry(repoRoot, tool, action, target, pattern string) error {
	path := logPath(repoRoot)

	prev, err := lastHash(path)
	if err != nil {
		return err
	}

	e := Entry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Tool:    tool,
		Action:  action,
		Target:  target,
		Pattern: pattern,
		Prev:    prev,
	}
	e.Hash = computeHash(e)

	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintf(f, "%s\n", b)
	return err
}

// LoadEntries reads and parses all entries from .cifra/ai-secure.log.
// Returns nil (not an error) when the log does not exist.
func LoadEntries(repoRoot string) ([]Entry, error) {
	b, err := os.ReadFile(logPath(repoRoot))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	var entries []Entry
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("parse audit log entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// VerifyChain checks that the hash chain in entries is intact.
// Returns the first error found, or nil if the chain is valid.
func VerifyChain(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		if e.Prev != prev {
			return fmt.Errorf("chain broken at entry %d: expected prev=%q, got %q", i, prev, e.Prev)
		}
		expected := computeHash(e)
		if e.Hash != expected {
			return fmt.Errorf("hash mismatch at entry %d (tool=%s action=%s)", i, e.Tool, e.Action)
		}
		prev = e.Hash
	}
	return nil
}

// computeHash returns SHA256(time|tool|action|target|pattern|prev) as hex.
// The Hash field of e is intentionally excluded so the digest is deterministic.
func computeHash(e Entry) string {
	content := strings.Join([]string{e.Time, e.Tool, e.Action, e.Target, e.Pattern, e.Prev}, "|")
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// lastHash returns the Hash field of the last entry in path, or "" if the log
// is empty or does not exist.
func lastHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read audit log: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var e Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			return e.Hash, nil
		}
	}
	return "", nil
}

func logPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".cifra", logFile)
}
