package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ---- helpers ----------------------------------------------------------------

// gitAddFile writes content to relPath inside dir and stages it.
func gitAddFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
	if out, err := exec.Command("git", "-C", dir, "add", relPath).CombinedOutput(); err != nil { //nolint:gosec // test helper
		t.Fatalf("git add %s: %v\n%s", relPath, err, out)
	}
}

// gitInitDirWithConfig creates a temp git repo with user config so commits work.
func gitInitDirWithConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil { //nolint:gosec // test helper
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("git", "init", dir)
	run("git", "-C", dir, "config", "user.email", "test@example.com")
	run("git", "-C", dir, "config", "user.name", "Test")
	return dir
}

// gitCommitEmpty creates an initial empty commit so git ls-files works.
func gitCommitEmpty(t *testing.T, dir string) {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "commit", "--allow-empty", "-m", "init").CombinedOutput() //nolint:gosec // test helper
	if err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

// ---- DefaultRules -----------------------------------------------------------

func TestDefaultRules_ReturnRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatal("DefaultRules returned empty slice")
	}
	ids := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule has empty ID")
		}
		if r.Pattern == nil {
			t.Errorf("rule %q has nil Pattern", r.ID)
		}
		if ids[r.ID] {
			t.Errorf("duplicate rule ID: %q", r.ID)
		}
		ids[r.ID] = true
	}
}

// ---- ParseSeverity & SeverityAtLeast ----------------------------------------

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"unknown", SeverityHigh},
		{"", SeverityHigh},
	}
	for _, tc := range cases {
		got := ParseSeverity(tc.in)
		if got != tc.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		s, min Severity
		want   bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityMedium, SeverityHigh, false},
		{SeverityMedium, SeverityMedium, true},
		{SeverityHigh, SeverityMedium, true},
	}
	for _, tc := range cases {
		got := SeverityAtLeast(tc.s, tc.min)
		if got != tc.want {
			t.Errorf("SeverityAtLeast(%q, %q) = %v, want %v", tc.s, tc.min, got, tc.want)
		}
	}
}

// ---- shannonEntropy (unexported) -------------------------------------------

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		s        string
		wantHigh bool // >= 4.5
	}{
		// Repeated single character = 0 entropy
		{"aaaa", false},
		// Short dictionary word = low entropy
		{"password", false},
		// Pure hex (max 4.0 bits per char, 16 symbols) — does NOT reach 4.5
		{"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", false},
		// Mixed-case alphanumeric (62 symbols) — clearly above 4.5
		{"aJ8kQm9nXp2rTs4vYw6ZbCdEfGhIjKlMn", true},
		// Empty string
		{"", false},
	}
	for _, tc := range cases {
		h := shannonEntropy(tc.s)
		got := h >= 4.5
		if got != tc.wantHigh {
			t.Errorf("shannonEntropy(%q) = %.2f, wantHigh=%v", tc.s, h, tc.wantHigh)
		}
	}
}

// ---- parseHunkStart (unexported) -------------------------------------------

func TestParseHunkStart(t *testing.T) {
	cases := []struct {
		line   string
		want   int
		wantOK bool
	}{
		{"@@ -0,0 +1,5 @@", 1, true},
		{"@@ -1,3 +42,7 @@", 42, true},
		{"@@ -1 +1 @@", 1, true},
		{"not a hunk header", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseHunkStart(tc.line)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("parseHunkStart(%q) = (%d, %v), want (%d, %v)", tc.line, got, ok, tc.want, tc.wantOK)
		}
	}
}

// ---- ScanDiff ---------------------------------------------------------------

func buildDiff(file, content string) string {
	lines := strings.Split(content, "\n")
	var sb strings.Builder
	sb.WriteString("diff --git a/" + file + " b/" + file + "\n")
	sb.WriteString("index 0000000..1111111 100644\n")
	sb.WriteString("--- /dev/null\n")
	sb.WriteString("+++ b/" + file + "\n")
	sb.WriteString("@@ -0,0 +1," + strconv.Itoa(len(lines)) + " @@\n")
	for _, l := range lines {
		sb.WriteString("+" + l + "\n")
	}
	return sb.String()
}

func TestScanDiff_EmptyDiff(t *testing.T) {
	matches := ScanDiff("", DefaultRules(), nil)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty diff, got %d", len(matches))
	}
}

func TestScanDiff_DetectsGitHubPAT(t *testing.T) {
	diff := buildDiff("config.go", `GITHUB_TOKEN=ghp_1234567890123456789012345678901234ab`) //nolint:gosec // G101: test fixture
	matches := ScanDiff(diff, DefaultRules(), nil)
	found := findByRuleID(matches, "github-pat")
	if found == nil {
		t.Fatal("expected github-pat match, got none")
	}
	if found.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", found.Severity)
	}
	if found.Line != 1 {
		t.Errorf("line = %d, want 1", found.Line)
	}
}

func TestScanDiff_DetectsAWSAccessKeyID(t *testing.T) {
	diff := buildDiff("infra.tf", `aws_access_key = "AKIAIOSFODNN7EXAMPLE"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "aws-access-key-id") == nil {
		t.Fatal("expected aws-access-key-id match")
	}
}

func TestScanDiff_DetectsOpenAIKey(t *testing.T) {
	diff := buildDiff("app.py", `OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "openai-api-key") == nil {
		t.Fatal("expected openai-api-key match")
	}
}

func TestScanDiff_DetectsStripeKey(t *testing.T) {
	diff := buildDiff("payment.js", `const stripeKey = "sk_live_abcdefghijklmnopqrstuvwx"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "stripe-secret-key") == nil {
		t.Fatal("expected stripe-secret-key match")
	}
}

func TestScanDiff_DetectsSlackToken(t *testing.T) {
	diff := buildDiff("notify.go", `token := "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "slack-token") == nil {
		t.Fatal("expected slack-token match")
	}
}

func TestScanDiff_DetectsPrivateKeyPEM(t *testing.T) {
	diff := buildDiff("keys/server.key", `-----BEGIN RSA PRIVATE KEY-----`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "private-key-pem") == nil {
		t.Fatal("expected private-key-pem match")
	}
}

func TestScanDiff_DetectsEnvFile(t *testing.T) {
	diff := "diff --git a/.env b/.env\nindex 0000000..1111111 100644\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+KEY=value\n"
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "env-file") == nil {
		t.Fatal("expected env-file match")
	}
}

func TestScanDiff_DetectsEnvFileDotLocal(t *testing.T) {
	diff := "diff --git a/.env.local b/.env.local\nindex 0000000..1111111 100644\n--- /dev/null\n+++ b/.env.local\n@@ -0,0 +1 @@\n+KEY=value\n"
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "env-file") == nil {
		t.Fatal("expected env-file match for .env.local")
	}
}

func TestScanDiff_DoesNotFlagRegularFile(t *testing.T) {
	diff := buildDiff("README.md", "# Hello World\n\nSome documentation text.")
	matches := ScanDiff(diff, DefaultRules(), nil)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for innocent file, got %d", len(matches))
	}
}

func TestScanDiff_SkipsDeletedLines(t *testing.T) {
	//nolint:gosec // G101: test fixture — intentionally placing a fake token in a deleted diff line
	diff := "diff --git a/config.go b/config.go\nindex abc..def 100644\n--- a/config.go\n+++ b/config.go\n@@ -1 +0,0 @@\n-GITHUB_TOKEN=ghp_1234567890123456789012345678901234ab\n"
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "github-pat") != nil {
		t.Error("deleted line triggered a match — should only flag additions")
	}
}

func TestScanDiff_LineNumbersAreAccurate(t *testing.T) {
	content := "package main\n\nconst tok = \"ghp_1234567890123456789012345678901234ab\"" //nolint:gosec // G101: test fixture
	diff := buildDiff("main.go", content)
	matches := ScanDiff(diff, DefaultRules(), nil)
	m := findByRuleID(matches, "github-pat")
	if m == nil {
		t.Fatal("expected github-pat match")
	}
	if m.Line != 3 {
		t.Errorf("line = %d, want 3", m.Line)
	}
}

func TestScanDiff_RespectsIgnoredFile(t *testing.T) {
	diff := buildDiff("testdata/fake.key", `-----BEGIN RSA PRIVATE KEY-----`)
	matches := ScanDiff(diff, DefaultRules(), []string{"testdata/*"})
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for ignored file, got %d", len(matches))
	}
}

func TestScanDiff_EntropyDetection(t *testing.T) {
	diff := buildDiff("config.yml", `SECRET_KEY: "aJ8kQm9nXp2rTs4vYw6ZbCdEfGhIjKlMn"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "high-entropy-secret") == nil {
		t.Error("expected high-entropy-secret match for high-entropy secret value")
	}
}

func TestScanDiff_EntropyIgnoresLowEntropy(t *testing.T) {
	diff := buildDiff("config.yml", `PASSWORD: "aaaaaaaaaaaaaaaaaaaaaa"`)
	matches := ScanDiff(diff, DefaultRules(), nil)
	if findByRuleID(matches, "high-entropy-secret") != nil {
		t.Error("low-entropy value should not trigger entropy rule")
	}
}

// ---- LoadIgnorePatterns -----------------------------------------------------

func TestLoadIgnorePatterns_ReturnsNilWhenNoFile(t *testing.T) {
	dir := t.TempDir()
	patterns, err := LoadIgnorePatterns(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patterns != nil {
		t.Errorf("expected nil patterns, got %v", patterns)
	}
}

func TestLoadIgnorePatterns_ParsesPatternsAndSkipsComments(t *testing.T) {
	dir := t.TempDir()
	content := "# This is a comment\n\ntestdata/*\n*.example\n# another comment\nfixtures/\n"
	if err := os.WriteFile(filepath.Join(dir, ".cifraignore"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns, err := LoadIgnorePatterns(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"testdata/*", "*.example", "fixtures/"}
	if len(patterns) != len(want) {
		t.Fatalf("patterns = %v, want %v", patterns, want)
	}
	for i, p := range patterns {
		if p != want[i] {
			t.Errorf("patterns[%d] = %q, want %q", i, p, want[i])
		}
	}
}

// ---- ScanFiles --------------------------------------------------------------

func TestScanFiles_DetectsSecretInTrackedFile(t *testing.T) {
	dir := gitInitDirWithConfig(t)
	gitCommitEmpty(t, dir)

	gitAddFile(t, dir, "secrets.go", `token := "ghp_1234567890123456789012345678901234ab"`)             //nolint:gosec // G101: test fixture
	if out, err := exec.Command("git", "-C", dir, "commit", "-m", "add").CombinedOutput(); err != nil { //nolint:gosec // test helper
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	matches, err := ScanFiles(dir, DefaultRules(), nil)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if findByRuleID(matches, "github-pat") == nil {
		t.Error("expected github-pat match in tracked file")
	}
}

func TestScanFiles_RespectsIgnoredFile(t *testing.T) {
	dir := gitInitDirWithConfig(t)
	gitCommitEmpty(t, dir)

	gitAddFile(t, dir, "testdata/fixture.go", `key := "ghp_1234567890123456789012345678901234ab"`)      //nolint:gosec // G101: test fixture
	if out, err := exec.Command("git", "-C", dir, "commit", "-m", "add").CombinedOutput(); err != nil { //nolint:gosec // test helper
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	matches, err := ScanFiles(dir, DefaultRules(), []string{"testdata/*"})
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if findByRuleID(matches, "github-pat") != nil {
		t.Error("github-pat match should be suppressed by .cifraignore")
	}
}

func TestScanFiles_NoMatchesForCleanRepo(t *testing.T) {
	dir := gitInitDirWithConfig(t)
	gitCommitEmpty(t, dir)

	gitAddFile(t, dir, "main.go", `package main

func main() {}`)
	if out, err := exec.Command("git", "-C", dir, "commit", "-m", "add").CombinedOutput(); err != nil { //nolint:gosec // test helper
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	matches, err := ScanFiles(dir, DefaultRules(), nil)
	if err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for clean repo, got %d", len(matches))
	}
}

// ---- helper -----------------------------------------------------------------

func findByRuleID(matches []Match, id string) *Match {
	for i := range matches {
		if matches[i].RuleID == id {
			return &matches[i]
		}
	}
	return nil
}
