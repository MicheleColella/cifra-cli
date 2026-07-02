package hook

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// hookBeginMarker and hookEndMarker delimit the envault-managed block inside the
// pre-commit hook file. Only the lines between (and including) these markers are
// touched on install or uninstall — any surrounding content is left intact.
const (
	hookBeginMarker = "# --- BEGIN envault pre-commit hook ---"
	hookEndMarker   = "# --- END envault pre-commit hook ---"

	// hookVersionMarker is embedded in the script body so InstallGitHook can
	// detect and auto-upgrade outdated v1 blocks on reinstall.
	hookVersionMarker = "# envault-hook-version: 2"
)

// hookScriptBody is the POSIX-sh script that runs inside the envault block.
// It delegates to `envault scan --staged` when the binary is on PATH and falls
// back to minimal inline checks when it is not (e.g. fresh clone before install).
const hookScriptBody = `# Envault: block commits that may contain plaintext secrets.
# envault-hook-version: 2
# Remove with: envault hook install --git --uninstall

# Only run inside an envault-managed repo.
if [ ! -d ".envault" ]; then
  exit 0
fi

# Prefer the Go scanner: entropy + 12+ patterns + .envaultignore support.
if command -v envault >/dev/null 2>&1; then
  envault scan --staged
  exit $?
fi

# Fallback: envault not on PATH — minimal inline checks.
_envault_fail() {
  printf '\033[0;31menvault:\033[0m %s\n' "$1" >&2
  printf '  Seal it with: envault add <KEY>\n' >&2
  printf '  To bypass (not recommended): git commit --no-verify\n' >&2
  exit 1
}

_staged=$(git diff --cached --name-only 2>/dev/null)
_diff_adds=$(git diff --cached -U0 2>/dev/null | grep '^+' | grep -v '^+++' || true)

if printf '%s\n' "$_staged" | grep -qE '(^|/)\.env(\.[a-zA-Z0-9]+)?$'; then
  _envault_fail ".env file staged for commit — use envault to store secrets instead"
fi
if printf '%s\n' "$_diff_adds" | grep -qE '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY'; then
  _envault_fail "private key material detected in staged diff"
fi
if printf '%s\n' "$_diff_adds" | grep -qE '(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{32,})'; then
  _envault_fail "known API token pattern detected in staged diff"
fi`

// envaultBlock is the complete envault-managed section including both markers.
var envaultBlock = hookBeginMarker + "\n" + hookScriptBody + "\n" + hookEndMarker + "\n"

// InstallGitHook installs the Envault pre-commit hook in the Git repo at repoRoot.
//
//   - If no pre-commit hook exists, a new one is created with a #!/bin/sh shebang.
//   - If one exists, the Envault block is appended after the existing content.
//   - If the Envault block is already present, the call is a no-op.
//
// The resulting file is always made executable (0755).
func InstallGitHook(repoRoot string) error {
	if _, err := os.Stat(filepath.Join(repoRoot, ".git")); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s is not a git repository", repoRoot)
	}

	hooksDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	existing, err := os.ReadFile(hookPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read pre-commit hook: %w", err)
	}
	content := string(existing)

	if strings.Contains(content, hookBeginMarker) {
		if strings.Contains(content, hookVersionMarker) {
			return nil // already at current version, no-op
		}
		// Outdated v1 block found — replace it with the current version.
		content = stripEnvaultBlock(content)
	}

	var newContent string
	if content == "" {
		newContent = "#!/bin/sh\n" + envaultBlock
	} else {
		// Exactly one "\n" separates existing content from the block, whether
		// or not content already ended in a newline — stripEnvaultBlock
		// reverses this unconditionally, which is what makes an
		// install+uninstall cycle restore the original byte-for-byte in every
		// case (already-terminated, not terminated, CRLF, or already ending
		// in a blank line).
		newContent = content + "\n" + envaultBlock
	}

	if err := os.WriteFile(hookPath, []byte(newContent), 0o755); err != nil { //nolint:gosec // hook scripts must be executable
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	return nil
}

// UninstallGitHook removes the Envault block from the pre-commit hook at repoRoot.
// If the file would be empty (or contain only a shebang) after removal, it is
// deleted to fully restore the prior state. Returns nil if the hook was not installed.
func UninstallGitHook(repoRoot string) error {
	hooksDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return err
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	data, err := os.ReadFile(hookPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // not installed
		}
		return fmt.Errorf("read pre-commit hook: %w", err)
	}

	stripped := stripEnvaultBlock(string(data))

	trimmed := strings.TrimSpace(stripped)
	if trimmed == "" || trimmed == "#!/bin/sh" || trimmed == "#!/usr/bin/env sh" {
		return os.Remove(hookPath)
	}

	return os.WriteFile(hookPath, []byte(stripped), 0o755) //nolint:gosec // hook scripts must be executable
}

// IsGitHookInstalled reports whether the Envault block is present in the
// pre-commit hook for the Git repo at repoRoot.
func IsGitHookInstalled(repoRoot string) bool {
	hooksDir, err := resolveHooksDir(repoRoot)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(hooksDir, "pre-commit"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookBeginMarker)
}

// resolveHooksDir returns the effective git hooks directory for repoRoot,
// respecting core.hooksPath if set in the local git config.
func resolveHooksDir(repoRoot string) (string, error) {
	out, err := exec.Command("git", "-C", repoRoot, "config", "--local", "core.hooksPath").Output() //nolint:gosec // repoRoot is derived from os.Getwd()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(repoRoot, p)
			}
			return p, nil
		}
	}
	return filepath.Join(repoRoot, ".git", "hooks"), nil
}

// stripEnvaultBlock removes the envault-managed block (BEGIN marker through END
// marker, inclusive) from content, plus the single "\n" separator
// InstallGitHook always adds immediately before it (see InstallGitHook — it
// adds exactly one "\n" whether or not content already ended in a newline,
// specifically so this strip is unconditional and exact). It operates on raw
// byte offsets rather than re-tokenizing and rejoining lines, so everything
// outside the deleted range — including CRLF line endings and the file's own
// trailing-newline state — is preserved byte-for-byte. Returns the modified
// content; the original is never mutated.
func stripEnvaultBlock(content string) string {
	beginIdx := strings.Index(content, hookBeginMarker)
	if beginIdx == -1 {
		return content
	}
	endIdx := strings.Index(content, hookEndMarker)
	if endIdx == -1 || endIdx < beginIdx {
		return content
	}

	lineStart := 0
	if nl := strings.LastIndexByte(content[:beginIdx], '\n'); nl != -1 {
		lineStart = nl + 1
	}

	lineEnd := endIdx + len(hookEndMarker)
	if nl := strings.IndexByte(content[lineEnd:], '\n'); nl != -1 {
		lineEnd += nl + 1
	} else {
		lineEnd = len(content)
	}

	before := strings.TrimSuffix(content[:lineStart], "\n")
	after := content[lineEnd:]
	return before + after
}
