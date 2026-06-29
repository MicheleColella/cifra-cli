package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MicheleColella/envault-cli/internal/hook"
	"github.com/MicheleColella/envault-cli/internal/ui"
)

// --- hook install --claude ---

func TestRunHookInstallClaude_InstallsHook(t *testing.T) {
	dir := t.TempDir()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallClaude(dir); err != nil {
		t.Fatalf("runHookInstallClaude: %v", err)
	}

	if !hook.IsClaudeHookInstalled(dir) {
		t.Error("hook not installed after runHookInstallClaude")
	}
	if !strings.Contains(out.String(), "installed") {
		t.Errorf("expected 'installed' in output, got %q", out.String())
	}
}

func TestRunHookInstallClaude_AlreadyInstalled(t *testing.T) {
	dir := t.TempDir()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallClaude(dir); err != nil {
		t.Fatalf("first install: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runHookInstallClaude(dir); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(out.String(), "already installed") {
		t.Errorf("expected 'already installed' on second call, got %q", out.String())
	}
}

func TestRunHookUninstallClaude_RemovesHook(t *testing.T) {
	dir := t.TempDir()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallClaude(dir); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := runHookUninstallClaude(dir); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if hook.IsClaudeHookInstalled(dir) {
		t.Error("hook still reported as installed after uninstall")
	}
}

func TestHookInstallCmd_ClaudeUninstallFlagWorks(t *testing.T) {
	dir := t.TempDir()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runHookInstallClaude(dir); err != nil {
		t.Fatalf("install: %v", err)
	}

	root := newRootCmd("dev")
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	root.SetArgs([]string{"hook", "install", "--claude", "--uninstall"})
	if err := root.Execute(); err != nil {
		t.Fatalf("hook install --claude --uninstall: %v", err)
	}

	if hook.IsClaudeHookInstalled(dir) {
		t.Error("hook still installed after --uninstall")
	}
}

// --- hook preuse ---

func TestRunHookPreuse_InjectsClaudeCodeEnv(t *testing.T) {
	dir := t.TempDir()

	// Create .envault/ so isEnvaultDir returns true.
	_ = os.MkdirAll(filepath.Join(dir, ".envault"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]interface{}{
			"command": "npm install",
		},
	}
	b, _ := json.Marshal(input)
	r := bytes.NewReader(b)
	var w bytes.Buffer

	if err := runHookPreuse(r, &w); err != nil {
		t.Fatalf("runHookPreuse: %v", err)
	}

	if w.Len() == 0 {
		t.Fatal("expected output from preuse handler, got nothing")
	}

	var out map[string]interface{}
	if err := json.Unmarshal(w.Bytes(), &out); err != nil {
		t.Fatalf("output not valid JSON: %v — raw: %s", err, w.String())
	}

	if out["type"] != "input_replace" {
		t.Errorf("expected type=input_replace, got %v", out["type"])
	}

	data, _ := out["data"].(map[string]interface{})
	cmd, _ := data["command"].(string)
	if !strings.HasPrefix(cmd, "CLAUDE_CODE=1 ") {
		t.Errorf("expected command to start with CLAUDE_CODE=1, got: %q", cmd)
	}
	if !strings.Contains(cmd, "npm install") {
		t.Errorf("original command not preserved, got: %q", cmd)
	}
}

func TestRunHookPreuse_NoopOutsideEnvaultRepo(t *testing.T) {
	dir := t.TempDir() // no .envault/

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]interface{}{
			"command": "echo hello",
		},
	}
	b, _ := json.Marshal(input)
	r := bytes.NewReader(b)
	var w bytes.Buffer

	if err := runHookPreuse(r, &w); err != nil {
		t.Fatalf("runHookPreuse: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output outside envault repo, got: %s", w.String())
	}
}

func TestRunHookPreuse_NoopForNonBashTool(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".envault"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name": "Read",
		"tool_input": map[string]interface{}{
			"file_path": "/etc/hosts",
		},
	}
	b, _ := json.Marshal(input)
	r := bytes.NewReader(b)
	var w bytes.Buffer

	if err := runHookPreuse(r, &w); err != nil {
		t.Fatalf("runHookPreuse: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for non-Bash tool, got: %s", w.String())
	}
}

func TestRunHookPreuse_AlreadyInjected(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".envault"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]interface{}{
			"command": "CLAUDE_CODE=1 npm test",
		},
	}
	b, _ := json.Marshal(input)
	r := bytes.NewReader(b)
	var w bytes.Buffer

	if err := runHookPreuse(r, &w); err != nil {
		t.Fatalf("runHookPreuse: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output when CLAUDE_CODE=1 already set, got: %s", w.String())
	}
}

func TestRunHookPreuse_InvalidJSONIsNoop(t *testing.T) {
	r := strings.NewReader("not json at all")
	var w bytes.Buffer
	if err := runHookPreuse(r, &w); err != nil {
		t.Fatalf("unexpected error on invalid JSON: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for invalid JSON input, got: %s", w.String())
	}
}
