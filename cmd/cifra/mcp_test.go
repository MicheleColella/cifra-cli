package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/mcp"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

// silenceUI redirects ui.Out/ui.Err to buffers for the test and restores the
// real writers on cleanup — the MCP handlers assume this (see withSilentUI).
func silenceUI(t *testing.T) {
	t.Helper()
	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})
}

// withMemKeychain swaps openKeychainForMCP for a factory returning kc, so
// tests never touch the real OS keychain, and restores it on cleanup.
func withMemKeychain(t *testing.T, kc keychain.Store) {
	t.Helper()
	old := openKeychainForMCP
	openKeychainForMCP = func() (keychain.Store, error) { return kc, nil }
	t.Cleanup(func() { openKeychainForMCP = old })
}

// findTool locates a registered tool by name or fails the test.
func findTool(t *testing.T, tools []mcp.Tool, name string) mcp.Tool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not registered", name)
	return mcp.Tool{}
}

func callTool(t *testing.T, tools []mcp.Tool, name string, args string) (interface{}, error) {
	t.Helper()
	tool := findTool(t, tools, name)
	return tool.Handler(json.RawMessage(args))
}

func TestMCPTools_Registry(t *testing.T) {
	tools := mcpTools(t.TempDir())
	want := []string{
		"cifra_status", "cifra_list", "cifra_rotate",
		"cifra_run", "cifra_protect", "cifra_push", "cifra_pull",
	}
	if len(tools) != len(want) {
		t.Fatalf("expected %d tools, got %d", len(want), len(tools))
	}
	for _, name := range want {
		findTool(t, tools, name)
	}
}

func TestMCPStatus_UninitializedVault(t *testing.T) {
	tools := mcpTools(t.TempDir())
	result, err := callTool(t, tools, "cifra_status", `{}`)
	if err != nil {
		t.Fatalf("cifra_status: %v", err)
	}
	res, ok := result.(statusResult)
	if !ok {
		t.Fatalf("expected statusResult, got %T", result)
	}
	if res.Initialized {
		t.Error("expected Initialized=false for a bare temp dir")
	}
}

func TestMCPStatus_InitializedVault(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")
	silenceUI(t)
	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	tools := mcpTools(root)
	result, err := callTool(t, tools, "cifra_status", `{}`)
	if err != nil {
		t.Fatalf("cifra_status: %v", err)
	}
	res := result.(statusResult)
	if !res.Initialized || res.Recipients != 1 || res.Secrets != 1 {
		t.Errorf("unexpected status: %+v", res)
	}
}

func TestMCPList_NotInitialized(t *testing.T) {
	tools := mcpTools(t.TempDir())
	_, err := callTool(t, tools, "cifra_list", `{}`)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected not-initialized error, got %v", err)
	}
}

func TestMCPList_ReturnsEntries(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")
	silenceUI(t)
	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	tools := mcpTools(root)
	result, err := callTool(t, tools, "cifra_list", `{}`)
	if err != nil {
		t.Fatalf("cifra_list: %v", err)
	}
	entries := result.([]listEntry)
	if len(entries) != 1 || entries[0].Name != "KEY" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestMCPTools_AddNotExposed(t *testing.T) {
	// cifra_add would require Claude to construct the plaintext value as a
	// tool argument — the same plaintext-exposure risk that already excludes
	// cat/export/import/key * from the MCP surface. Sealing a brand-new
	// secret must stay a terminal-only operation (see preuse.go's block on
	// `cifra add`/`cifra set` via Bash).
	tools := mcpTools(t.TempDir())
	for _, tool := range tools {
		if tool.Name == "cifra_add" {
			t.Fatal("cifra_add must not be exposed as an MCP tool")
		}
	}
}

func TestMCPRotate_Success(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")
	silenceUI(t)
	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}
	withMemKeychain(t, kc)

	tools := mcpTools(root)
	result, err := callTool(t, tools, "cifra_rotate", `{"name":"KEY"}`)
	if err != nil {
		t.Fatalf("cifra_rotate: %v", err)
	}
	summary := result.(entrySummary)
	if !summary.OK || summary.Name != "KEY" {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestMCPRotate_NoPrivateKey(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")
	silenceUI(t)
	if err := runAdd(root, "KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}
	withMemKeychain(t, newMemStore()) // empty — no key sealed

	tools := mcpTools(root)
	_, err := callTool(t, tools, "cifra_rotate", `{"name":"KEY"}`)
	if err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key' error, got %v", err)
	}
}

func TestMCPRun_InjectsSecretsAndCapturesOutput(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")
	silenceUI(t)
	if err := runAdd(root, "CIFRA_TEST_VAR", []byte("hello-from-vault")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}
	withMemKeychain(t, kc)

	tools := mcpTools(root)
	result, err := callTool(t, tools, "cifra_run", `{"command":["printenv","CIFRA_TEST_VAR"]}`)
	if err != nil {
		t.Fatalf("cifra_run: %v", err)
	}
	res := result.(runResult)
	if !res.OK || res.ExitCode != 0 {
		t.Errorf("unexpected result: %+v", res)
	}
	if !strings.Contains(res.Stdout, "hello-from-vault") {
		t.Errorf("expected secret value in captured stdout, got %q", res.Stdout)
	}
}

func TestMCPRun_ExitCodePropagatedNotAsError(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")
	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}
	withMemKeychain(t, kc)

	tools := mcpTools(root)
	result, err := callTool(t, tools, "cifra_run", `{"command":["false"]}`)
	if err != nil {
		t.Fatalf("cifra_run should report a nonzero exit via the result, not an error: %v", err)
	}
	res := result.(runResult)
	if res.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1", res.ExitCode)
	}
}

func TestMCPRun_EmptyCommand(t *testing.T) {
	root := initVaultRoot(t)
	tools := mcpTools(root)
	_, err := callTool(t, tools, "cifra_run", `{"command":[]}`)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestMCPRun_OnlyAndExceptMutuallyExclusive(t *testing.T) {
	root := initVaultRoot(t)
	tools := mcpTools(root)
	_, err := callTool(t, tools, "cifra_run",
		`{"command":["true"],"only":["A"],"except":["B"]}`)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestMCPProtect_AddListRemove(t *testing.T) {
	root := initVaultRoot(t)
	tools := mcpTools(root)

	if _, err := callTool(t, tools, "cifra_protect", `{"action":"add","pattern":"*.pem"}`); err != nil {
		t.Fatalf("add: %v", err)
	}

	result, err := callTool(t, tools, "cifra_protect", `{"action":"list"}`)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	patterns := result.(map[string]interface{})["patterns"].([]string)
	if len(patterns) != 1 || patterns[0] != "*.pem" {
		t.Fatalf("unexpected patterns: %v", patterns)
	}

	if _, err := callTool(t, tools, "cifra_protect", `{"action":"remove","pattern":"*.pem"}`); err != nil {
		t.Fatalf("remove: %v", err)
	}
	result, err = callTool(t, tools, "cifra_protect", `{"action":"list"}`)
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	patterns = result.(map[string]interface{})["patterns"].([]string)
	if len(patterns) != 0 {
		t.Fatalf("expected no patterns after remove, got %v", patterns)
	}
}

func TestMCPProtect_UnknownAction(t *testing.T) {
	root := initVaultRoot(t)
	tools := mcpTools(root)
	_, err := callTool(t, tools, "cifra_protect", `{"action":"bogus"}`)
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("expected unknown-action error, got %v", err)
	}
}

func TestMCPProtect_Encrypt(t *testing.T) {
	root := initVaultRoot(t)
	priv := addTestRecipient(t, root, "alice@example.com")
	kc := newMemStore()
	if err := kc.Seal("alice@example.com", priv[:]); err != nil {
		t.Fatalf("kc.Seal: %v", err)
	}
	withMemKeychain(t, kc)

	filePath := filepath.Join(root, "secret.pem")
	if err := os.WriteFile(filePath, []byte("-----BEGIN KEY-----"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tools := mcpTools(root)
	argsJSON := `{"action":"encrypt","file":"` + filePath + `"}`
	result, err := callTool(t, tools, "cifra_protect", argsJSON)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !result.(map[string]interface{})["ok"].(bool) {
		t.Errorf("expected ok=true, got %v", result)
	}
	if _, statErr := os.Stat(filePath); !os.IsNotExist(statErr) {
		t.Error("plaintext file should have been removed from disk")
	}
}

func TestMCPPush_ReportsMetadata(t *testing.T) {
	repo, _ := initTestRepo(t, "alice@test.com", "Alice")
	if err := runInit(repo, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	silenceUI(t)

	tools := mcpTools(repo)
	result, err := callTool(t, tools, "cifra_push", `{}`)
	if err != nil {
		t.Fatalf("cifra_push: %v", err)
	}
	m := result.(map[string]interface{})
	if m["ok"] != true {
		t.Errorf("expected ok=true, got %v", m)
	}
	if m["commit"] == "" {
		t.Error("expected a non-empty commit hash")
	}
}

func TestMCPPull_UpToDate(t *testing.T) {
	repo, _ := initTestRepo(t, "alice@test.com", "Alice")
	if err := runInit(repo, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	silenceUI(t)
	if err := runPush(repo); err != nil {
		t.Fatalf("runPush: %v", err)
	}

	tools := mcpTools(repo)
	result, err := callTool(t, tools, "cifra_pull", `{}`)
	if err != nil {
		t.Fatalf("cifra_pull: %v", err)
	}
	m := result.(map[string]interface{})
	if m["ok"] != true {
		t.Errorf("expected ok=true, got %v", m)
	}
	if len(m["added"].([]string)) != 0 {
		t.Errorf("expected no added entries, got %v", m["added"])
	}
}

func TestMCPServe_DryRunPrintsSchemas(t *testing.T) {
	cmd := newMCPServeCmd("test-version")
	cmd.SetArgs([]string{"--dry-run", "--project", t.TempDir()})

	var out bytes.Buffer
	cmd.SetOut(&out)
	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	_ = w.Close()
	os.Stdout = origStdout
	var captured bytes.Buffer
	_, _ = captured.ReadFrom(r)

	if err != nil {
		t.Fatalf("mcp serve --dry-run: %v", err)
	}

	var tools []map[string]interface{}
	if unmarshalErr := json.Unmarshal(captured.Bytes(), &tools); unmarshalErr != nil {
		t.Fatalf("output not a valid JSON array: %v — %q", unmarshalErr, captured.String())
	}
	if len(tools) != 7 {
		t.Errorf("expected 7 tool schemas, got %d", len(tools))
	}
}
