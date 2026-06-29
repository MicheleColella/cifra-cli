package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallClaudeHook_WritesSettingsFile(t *testing.T) {
	dir := t.TempDir()

	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("InstallClaudeHook: %v", err)
	}

	path := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("settings.json not created: %v", err)
	}

	var data map[string]interface{}
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatalf("settings.json not valid JSON: %v", err)
	}
}

func TestInstallClaudeHook_Idempotent(t *testing.T) {
	dir := t.TempDir()

	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("second install: %v", err)
	}

	// Ensure there is exactly one envault hook group in PreToolUse.
	data, _ := readSettings(claudeSettingsPath(dir))
	groups := preToolUseGroups(data)
	count := 0
	for _, g := range groups {
		if matchesEnvaultGroup(g) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 envault hook group after two installs, got %d", count)
	}
}

func TestIsClaudeHookInstalled_FalseBeforeInstall(t *testing.T) {
	dir := t.TempDir()
	if IsClaudeHookInstalled(dir) {
		t.Error("expected false before install")
	}
}

func TestIsClaudeHookInstalled_TrueAfterInstall(t *testing.T) {
	dir := t.TempDir()
	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("InstallClaudeHook: %v", err)
	}
	if !IsClaudeHookInstalled(dir) {
		t.Error("expected true after install")
	}
}

func TestUninstallClaudeHook_RemovesEntry(t *testing.T) {
	dir := t.TempDir()

	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := UninstallClaudeHook(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if IsClaudeHookInstalled(dir) {
		t.Error("hook still reported as installed after uninstall")
	}
}

func TestUninstallClaudeHook_NoopWhenNotInstalled(t *testing.T) {
	dir := t.TempDir()
	if err := UninstallClaudeHook(dir); err != nil {
		t.Fatalf("uninstall on clean dir: %v", err)
	}
}

func TestInstallClaudeHook_PreservesExistingKeys(t *testing.T) {
	dir := t.TempDir()

	// Write a settings.json with some pre-existing content.
	existing := map[string]interface{}{
		"theme": "dark",
		"hooks": map[string]interface{}{
			"Stop": []interface{}{
				map[string]interface{}{
					"matcher": "",
					"hooks": []interface{}{
						map[string]interface{}{"type": "command", "command": "echo done"},
					},
				},
			},
		},
	}
	clDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(clDir, 0o700)
	b, _ := json.MarshalIndent(existing, "", "  ")
	_ = os.WriteFile(filepath.Join(clDir, "settings.json"), b, 0o600)

	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("InstallClaudeHook: %v", err)
	}

	data, err := readSettings(claudeSettingsPath(dir))
	if err != nil {
		t.Fatalf("readSettings: %v", err)
	}

	// "theme" key must still be present.
	if data["theme"] != "dark" {
		t.Error("existing 'theme' key was overwritten")
	}

	// "Stop" hook must still be present.
	hooks := hooksMap(data)
	if _, ok := hooks["Stop"]; !ok {
		t.Error("existing 'Stop' hook was removed")
	}

	// Envault PreToolUse hook must also be present.
	if !IsClaudeHookInstalled(dir) {
		t.Error("envault hook not installed after merge")
	}
}

func TestUninstallClaudeHook_LeavesOtherHooksIntact(t *testing.T) {
	dir := t.TempDir()

	// Install envault + add another pre-tool-use group.
	if err := InstallClaudeHook(dir); err != nil {
		t.Fatalf("install: %v", err)
	}

	// Inject a second PreToolUse group manually.
	path := claudeSettingsPath(dir)
	data, _ := readSettings(path)
	hooks := hooksMap(data)
	groups := preToolUseGroups(data)
	groups = append(groups, map[string]interface{}{
		"matcher": "Bash",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "other-hook"},
		},
	})
	hooks["PreToolUse"] = groups
	data["hooks"] = hooks
	_ = writeSettings(path, data)

	// Uninstall envault hook.
	if err := UninstallClaudeHook(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	// Other hook must still be present.
	data, _ = readSettings(path)
	groups = preToolUseGroups(data)
	found := false
	for _, g := range groups {
		m, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		hooks2, _ := m["hooks"].([]interface{})
		for _, h := range hooks2 {
			hm, ok := h.(map[string]interface{})
			if ok && hm["command"] == "other-hook" {
				found = true
			}
		}
	}
	if !found {
		t.Error("other-hook was removed during envault uninstall")
	}
}
