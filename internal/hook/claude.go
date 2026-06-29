package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// claudeHookCommand is the envault subcommand registered as the PreToolUse hook.
// It reads the tool-call JSON from stdin and injects CLAUDE_CODE=1 into Bash commands.
const claudeHookCommand = "envault hook preuse"

// claudeHookID is a stable string we embed in the hook entry so we can find/remove it.
const claudeHookID = "envault"

// InstallClaudeHook writes a PreToolUse(Bash) hook entry into .claude/settings.json.
// Existing content is preserved; the function is idempotent.
func InstallClaudeHook(repoRoot string) error {
	path := claudeSettingsPath(repoRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create .claude directory: %w", err)
	}

	data, err := readSettings(path)
	if err != nil {
		return err
	}

	if isClaudeHookPresent(data) {
		return nil
	}

	addClaudeHook(data)

	return writeSettings(path, data)
}

// UninstallClaudeHook removes the envault PreToolUse hook from .claude/settings.json.
// Returns nil when the hook was not installed or the file does not exist.
func UninstallClaudeHook(repoRoot string) error {
	path := claudeSettingsPath(repoRoot)

	data, err := readSettings(path)
	if err != nil {
		return err
	}

	if !isClaudeHookPresent(data) {
		return nil
	}

	removeClaudeHook(data)
	return writeSettings(path, data)
}

// IsClaudeHookInstalled reports whether the envault hook is present in settings.json.
func IsClaudeHookInstalled(repoRoot string) bool {
	data, err := readSettings(claudeSettingsPath(repoRoot))
	if err != nil {
		return false
	}
	return isClaudeHookPresent(data)
}

// --- helpers ---

func claudeSettingsPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".claude", "settings.json")
}

// readSettings reads and parses settings.json as a generic map.
// Returns an empty map when the file does not exist.
func readSettings(path string) (map[string]interface{}, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read settings.json: %w", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse settings.json: %w", err)
	}
	return out, nil
}

func writeSettings(path string, data map[string]interface{}) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings.json: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write settings.json: %w", err)
	}
	return nil
}

// isClaudeHookPresent checks whether the envault hook entry is already in data.
func isClaudeHookPresent(data map[string]interface{}) bool {
	groups := preToolUseGroups(data)
	for _, g := range groups {
		if matchesEnvaultGroup(g) {
			return true
		}
	}
	return false
}

// addClaudeHook appends the envault hook group to PreToolUse.
func addClaudeHook(data map[string]interface{}) {
	hooks := hooksMap(data)
	groups := preToolUseGroups(data)
	groups = append(groups, envaultHookGroup())
	hooks["PreToolUse"] = groups
	data["hooks"] = hooks
}

// removeClaudeHook removes the envault hook group from PreToolUse.
func removeClaudeHook(data map[string]interface{}) {
	hooks := hooksMap(data)
	groups := preToolUseGroups(data)

	filtered := make([]interface{}, 0, len(groups))
	for _, g := range groups {
		if !matchesEnvaultGroup(g) {
			filtered = append(filtered, g)
		}
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(data, "hooks")
	} else {
		data["hooks"] = hooks
	}
}

// envaultHookGroup returns the map representation of the envault hook group entry.
func envaultHookGroup() map[string]interface{} {
	return map[string]interface{}{
		"matcher": "Bash",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": claudeHookCommand,
				// Stable ID used to locate/remove this entry.
				"_envault": claudeHookID,
			},
		},
	}
}

// matchesEnvaultGroup returns true when g is the envault-managed hook group.
func matchesEnvaultGroup(g interface{}) bool {
	m, ok := g.(map[string]interface{})
	if !ok {
		return false
	}
	hooks, _ := m["hooks"].([]interface{})
	for _, h := range hooks {
		hm, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if hm["_envault"] == claudeHookID {
			return true
		}
		// Legacy detection: match by command string.
		if hm["command"] == claudeHookCommand {
			return true
		}
	}
	return false
}

// hooksMap returns the "hooks" key from data as a map, creating it if missing.
func hooksMap(data map[string]interface{}) map[string]interface{} {
	if v, ok := data["hooks"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	m := map[string]interface{}{}
	data["hooks"] = m
	return m
}

// preToolUseGroups returns the PreToolUse array from hooks, or nil if absent.
func preToolUseGroups(data map[string]interface{}) []interface{} {
	hooks := hooksMap(data)
	v, ok := hooks["PreToolUse"]
	if !ok {
		return nil
	}
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}
