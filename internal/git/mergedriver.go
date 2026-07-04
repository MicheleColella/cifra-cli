package git

import (
	"os"
	"path/filepath"
	"strings"
)

// mergeDriverName is the git merge-driver key: `[merge "cifra"]` in .git/config
// and `merge=cifra` in .gitattributes.
const mergeDriverName = "cifra"

// gitAttributesLine routes secrets.enc merges to the cifra driver. It is committed
// via .gitattributes so it travels to teammates; the driver *definition* it points
// at lives in local .git/config (per clone) and is written by `cifra init` /
// `cifra init --upgrade`. That split is exactly why MergeDriverMisconfigured exists.
const gitAttributesLine = ".cifra/secrets.enc merge=cifra"

// RegisterMergeDriver defines the `cifra` merge driver in the repo's local
// .git/config so `git merge` runs `cifra merge %O %A %B` for secrets.enc.
// Idempotent and non-destructive: if a driver command is already set it is left
// untouched (never clobbers a user override). The command uses the PATH name
// `cifra` — the same convention the hooks and MCP server use — so it follows the
// user's installed binary across upgrades rather than pinning an absolute path.
func RegisterMergeDriver(repoRoot string) error {
	if IsMergeDriverRegistered(repoRoot) {
		return nil // already registered; do not overwrite
	}
	if err := gitRun(repoRoot, "config", "--local",
		"merge."+mergeDriverName+".name", "Cifra ciphertext-only secrets.enc merge"); err != nil {
		return err
	}
	return gitRun(repoRoot, "config", "--local",
		"merge."+mergeDriverName+".driver", "cifra merge %O %A %B")
}

// IsMergeDriverRegistered reports whether local .git/config defines the cifra
// merge driver command.
func IsMergeDriverRegistered(repoRoot string) bool {
	out, err := gitOutput(repoRoot, "config", "--local", "--get",
		"merge."+mergeDriverName+".driver")
	return err == nil && strings.TrimSpace(out) != ""
}

// EnsureGitAttributes appends the secrets.enc merge=cifra line to the repo's
// .gitattributes if absent, preserving any existing content (append-only, like
// the pre-commit hook installer's non-destructive contract). Reports whether it
// added the line.
func EnsureGitAttributes(repoRoot string) (bool, error) {
	path := filepath.Join(repoRoot, ".gitattributes")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if declaresMergeDriver(data) {
		return false, nil
	}
	var b strings.Builder
	b.Write(data)
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		b.WriteByte('\n')
	}
	b.WriteString(gitAttributesLine + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // .gitattributes is a committed, non-secret repo file — 0644 is correct
		return false, err
	}
	return true, nil
}

// VaultDeclaresMergeDriver reports whether .gitattributes routes secrets.enc to
// the cifra merge driver.
func VaultDeclaresMergeDriver(repoRoot string) bool {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".gitattributes"))
	if err != nil {
		return false
	}
	return declaresMergeDriver(data)
}

func declaresMergeDriver(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, ".cifra/secrets.enc") && strings.Contains(line, "merge="+mergeDriverName) {
			return true
		}
	}
	return false
}

// MergeDriverMisconfigured reports the fail-closed danger state: .gitattributes
// declares merge=cifra (so git routes secrets.enc merges to the driver) but the
// local .git/config does NOT define it. In that state git silently falls back to
// a text merge and corrupts the JSON store, so callers (e.g. `cifra pull`) must
// refuse and tell the user to run `cifra init --upgrade`.
func MergeDriverMisconfigured(repoRoot string) bool {
	return VaultDeclaresMergeDriver(repoRoot) && !IsMergeDriverRegistered(repoRoot)
}
