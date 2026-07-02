package scan

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Severity represents the urgency of a detected finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
)

var severityOrder = map[Severity]int{
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// SeverityAtLeast reports whether s is at or above min in the severity order.
func SeverityAtLeast(s, min Severity) bool {
	return severityOrder[s] >= severityOrder[min]
}

// ParseSeverity converts a string to Severity; unknown values default to High.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "medium":
		return SeverityMedium
	default:
		return SeverityHigh
	}
}

// Rule is a single secret-detection rule.
type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	Severity    Severity
	FileLevel   bool // match file name rather than line content
}

// Match is a single detection result.
type Match struct {
	File        string
	Line        int // 0 for file-level matches
	RuleID      string
	Description string
	Severity    Severity
	Snippet     string // truncated matched content or file path
}

// DefaultRules returns the built-in detection ruleset.
func DefaultRules() []Rule {
	return []Rule{
		// File-level
		{
			ID:          "env-file",
			Description: ".env file staged for commit",
			Pattern:     regexp.MustCompile(`(?i)^\.env(\.[a-zA-Z0-9]+)?$`),
			Severity:    SeverityHigh,
			FileLevel:   true,
		},
		// Critical: private key material
		{
			ID:          "private-key-pem",
			Description: "PEM-encoded private key",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY`),
			Severity:    SeverityCritical,
		},
		// Critical: cloud / platform credentials
		{
			ID:          "github-pat",
			Description: "GitHub personal access token",
			Pattern:     regexp.MustCompile(`(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})`),
			Severity:    SeverityCritical,
		},
		{
			ID:          "aws-access-key-id",
			Description: "AWS IAM access key ID",
			Pattern:     regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
			Severity:    SeverityCritical,
		},
		{
			ID:          "openai-api-key",
			Description: "OpenAI API key",
			Pattern:     regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{32,}`),
			Severity:    SeverityCritical,
		},
		{
			ID:          "stripe-secret-key",
			Description: "Stripe secret API key",
			Pattern:     regexp.MustCompile(`sk_(live|test)_[A-Za-z0-9]{24,}`),
			Severity:    SeverityCritical,
		},
		// High: SaaS tokens
		{
			ID:          "slack-token",
			Description: "Slack bot or user OAuth token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`),
			Severity:    SeverityHigh,
		},
		{
			ID:          "sendgrid-api-key",
			Description: "SendGrid API key",
			Pattern:     regexp.MustCompile(`SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43}`),
			Severity:    SeverityHigh,
		},
		{
			ID:          "google-api-key",
			Description: "Google / Firebase API key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity:    SeverityHigh,
		},
		{
			ID:          "npm-access-token",
			Description: "npm access token",
			Pattern:     regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
			Severity:    SeverityHigh,
		},
		{
			ID:          "twilio-account-sid",
			Description: "Twilio account SID",
			Pattern:     regexp.MustCompile(`\bAC[0-9a-f]{32}\b`),
			Severity:    SeverityHigh,
		},
		{
			ID:          "anthropic-api-key",
			Description: "Anthropic API key",
			Pattern:     regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{95}`),
			Severity:    SeverityHigh,
		},
	}
}

// entropyVarRe matches assignment lines where the variable name contains a
// credential keyword and the value is a long, potentially random string.
var entropyVarRe = regexp.MustCompile(
	`(?i)[A-Za-z0-9_]*(?:password|passwd|secret|token|key|passphrase|credential|auth)[A-Za-z0-9_]*\s*[=:]\s*["']?([A-Za-z0-9+/=_\-\.]{20,})["']?`,
)

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	runes := []rune(s)
	for _, c := range runes {
		freq[c]++
	}
	n := float64(len(runes))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// scanLine runs all content rules and the entropy check against a single line.
func scanLine(file string, lineNum int, content string, rules []Rule) []Match {
	var matches []Match
	for _, rule := range rules {
		if rule.FileLevel {
			continue
		}
		if rule.Pattern.MatchString(content) {
			matches = append(matches, Match{
				File:        file,
				Line:        lineNum,
				RuleID:      rule.ID,
				Description: rule.Description,
				Severity:    rule.Severity,
				Snippet:     snippetOf(content, 80),
			})
		}
	}
	// Entropy-based heuristic: flag high-entropy values near credential variable names.
	if sub := entropyVarRe.FindStringSubmatch(content); len(sub) >= 2 {
		if shannonEntropy(sub[1]) >= 4.5 {
			matches = append(matches, Match{
				File:        file,
				Line:        lineNum,
				RuleID:      "high-entropy-secret",
				Description: "high-entropy value near credential variable name",
				Severity:    SeverityMedium,
				Snippet:     snippetOf(content, 80),
			})
		}
	}
	return matches
}

// isIgnored reports whether path (or its base name) matches any glob in patterns.
func isIgnored(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, path); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	return false
}

// ScanDiff scans a unified diff (e.g. from `git diff --cached -U0`) for secrets.
// ignoredFiles contains gitignore-style glob patterns from .cifraignore.
func ScanDiff(diff string, rules []Rule, ignoredFiles []string) []Match {
	var (
		matches     []Match
		currentFile string
		lineNum     int
	)
	sc := bufio.NewScanner(strings.NewReader(diff))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ b/"):
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			if !isIgnored(currentFile, ignoredFiles) {
				for _, rule := range rules {
					if rule.FileLevel && rule.Pattern.MatchString(filepath.Base(currentFile)) {
						matches = append(matches, Match{
							File:        currentFile,
							Line:        0,
							RuleID:      rule.ID,
							Description: rule.Description,
							Severity:    rule.Severity,
							Snippet:     currentFile,
						})
					}
				}
			}
		case strings.HasPrefix(line, "@@ "):
			if start, ok := parseHunkStart(line); ok {
				lineNum = start - 1 // incremented on the first + line
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			lineNum++
			if !isIgnored(currentFile, ignoredFiles) {
				matches = append(matches, scanLine(currentFile, lineNum, line[1:], rules)...)
			}
		}
	}
	return matches
}

// ScanFiles scans all git-tracked files under repoRoot for secrets.
func ScanFiles(repoRoot string, rules []Rule, ignoredFiles []string) ([]Match, error) {
	out, err := exec.Command("git", "-C", repoRoot, "ls-files").Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	var matches []Match
	for _, relPath := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if relPath == "" || isIgnored(relPath, ignoredFiles) {
			continue
		}
		for _, rule := range rules {
			if rule.FileLevel && rule.Pattern.MatchString(filepath.Base(relPath)) {
				matches = append(matches, Match{
					File:        relPath,
					RuleID:      rule.ID,
					Description: rule.Description,
					Severity:    rule.Severity,
					Snippet:     relPath,
				})
			}
		}
		fullPath := filepath.Join(repoRoot, relPath)
		f, err := os.Open(fullPath) //nolint:gosec
		if err != nil {
			continue
		}
		lineNum := 0
		lsc := bufio.NewScanner(f)
		for lsc.Scan() {
			lineNum++
			matches = append(matches, scanLine(relPath, lineNum, lsc.Text(), rules)...)
		}
		_ = f.Close()
	}
	return matches, nil
}

// LoadIgnorePatterns reads .cifraignore from repoRoot and returns the glob
// patterns. Returns nil (not an error) when the file does not exist.
func LoadIgnorePatterns(repoRoot string) ([]string, error) {
	path := filepath.Join(repoRoot, ".cifraignore")
	f, err := os.Open(path) //nolint:gosec
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, sc.Err()
}

// parseHunkStart extracts the new-file start line number from a diff @@ header.
// "@@ -A,B +C,D @@" → returns C, true.
func parseHunkStart(line string) (int, bool) {
	i := strings.Index(line, " +")
	if i < 0 {
		return 0, false
	}
	rest := line[i+2:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

func snippetOf(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
