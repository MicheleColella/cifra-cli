package protect

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PrivatePathsFile is the filename inside .cifra/ that stores registered patterns.
const PrivatePathsFile = "private-paths"

// ErrPatternNotFound is returned when RemovePattern cannot find the target.
var ErrPatternNotFound = fmt.Errorf("pattern not found in private-paths")

// AddPattern registers pattern in .cifra/private-paths. Idempotent.
func AddPattern(repoRoot, pattern string) error {
	patterns, err := LoadPatterns(repoRoot)
	if err != nil {
		return err
	}
	for _, p := range patterns {
		if p == pattern {
			return nil
		}
	}
	return savePatterns(repoRoot, append(patterns, pattern))
}

// RemovePattern deletes pattern from .cifra/private-paths.
// Returns ErrPatternNotFound if the pattern is not registered.
func RemovePattern(repoRoot, pattern string) error {
	patterns, err := LoadPatterns(repoRoot)
	if err != nil {
		return err
	}
	filtered := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p != pattern {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == len(patterns) {
		return ErrPatternNotFound
	}
	return savePatterns(repoRoot, filtered)
}

// LoadPatterns reads .cifra/private-paths and returns the list of patterns.
// Returns an empty slice (not an error) when the file does not exist.
func LoadPatterns(repoRoot string) ([]string, error) {
	f, err := os.Open(patternsPath(repoRoot))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read private-paths: %w", err)
	}
	defer func() { _ = f.Close() }()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, sc.Err()
}

// MatchesAny checks whether targetPath matches any of the given patterns.
// Returns the first matching pattern and true, or ("", false) if no match.
// Matching strategy (in order):
//  1. filepath.Match(pattern, targetPath) — exact or glob match on full path
//  2. filepath.Match(pattern, filepath.Base(targetPath)) — basename match for simple names
//  3. Prefix directory match: pattern "config/" matches "config/secrets.json"
func MatchesAny(targetPath string, patterns []string) (string, bool) {
	clean := filepath.ToSlash(filepath.Clean(targetPath))
	base := filepath.Base(clean)
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, clean); ok {
			return p, true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return p, true
		}
		dir := strings.TrimSuffix(filepath.ToSlash(p), "/") + "/"
		if strings.HasPrefix(clean+"/", dir) {
			return p, true
		}
	}
	return "", false
}

// ContainsProtectedPath checks whether the given text (typically a Bash command
// string) contains any token that matches a protected pattern.
// Returns the first matching pattern and the matched token, or ("", "", false).
// This is a best-effort heuristic; adversarial bypass coverage is in v0.8.4.
func ContainsProtectedPath(text string, patterns []string) (pattern, token string, found bool) {
	// Tokenize on whitespace and common delimiters to extract path-like fragments.
	tokens := tokenize(text)
	for _, tok := range tokens {
		if p, ok := MatchesAny(tok, patterns); ok {
			return p, tok, true
		}
	}
	return "", "", false
}

func savePatterns(repoRoot string, patterns []string) error {
	path := patternsPath(repoRoot)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write private-paths: %w", err)
	}
	defer func() { _ = f.Close() }()
	for _, p := range patterns {
		if _, err := fmt.Fprintln(f, p); err != nil {
			return fmt.Errorf("write private-paths line: %w", err)
		}
	}
	return nil
}

func patternsPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".cifra", PrivatePathsFile)
}

// tokenize splits text into path-like fragments by splitting on whitespace and
// common shell delimiters (quotes, semicolons, pipes, redirects, parentheses).
func tokenize(text string) []string {
	// Replace common delimiters with spaces then split.
	replacer := strings.NewReplacer(
		"\"", " ", "'", " ", ";", " ", "|", " ", "&", " ",
		"(", " ", ")", " ", "<", " ", ">", " ", "`", " ",
		"$", " ", "{", " ", "}", " ", "=", " ", ":", " ",
	)
	normalized := replacer.Replace(text)
	raw := strings.Fields(normalized)

	// Keep only tokens that look like paths (contain "/" or ".") or simple names.
	result := make([]string, 0, len(raw))
	for _, tok := range raw {
		if tok != "" {
			result = append(result, tok)
		}
	}
	return result
}
