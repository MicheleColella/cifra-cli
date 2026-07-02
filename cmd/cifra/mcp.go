package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/mcp"
	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// openKeychainForMCP is a seam so tests can swap in an in-memory keychain.Store
// instead of touching the real OS keychain, the same way tests elsewhere in
// this package swap ui.Out for a buffer.
var openKeychainForMCP = openKeychain

func newMCPCmd(ver string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol server for Claude Code",
	}
	cmd.AddCommand(newMCPServeCmd(ver))
	return cmd
}

func newMCPServeCmd(ver string) *cobra.Command {
	var project string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Cifra MCP server (JSON-RPC 2.0 over stdio)",
		Long: "Exposes typed, JSON-Schema-validated tools so Claude Code can call Cifra\n" +
			"directly instead of invoking bash commands — parameters arrive as validated\n" +
			"JSON fields, not a free-form shell string, so there is no shell injection\n" +
			"vector. Secret values never appear in tool responses, only metadata\n" +
			"(name, algorithm, recipient count, timestamps).\n\n" +
			"Runs headless: any operation needing the private key requires\n" +
			"CIFRA_PASSPHRASE in the environment (no interactive prompt is possible\n" +
			"over stdio) and fails with a structured error otherwise.",
		RunE: func(_ *cobra.Command, _ []string) error {
			repoRoot := project
			if repoRoot == "" {
				wd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("get working directory: %w", err)
				}
				repoRoot = wd
			}

			srv := &mcp.Server{Name: "cifra", Version: ver, Tools: mcpTools(repoRoot)}
			if dryRun {
				return srv.PrintSchemas(os.Stdout)
			}
			return srv.Serve(os.Stdin, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project root (defaults to the current directory)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print every tool's JSON Schema and exit")
	return cmd
}

// withSilentUI redirects ui.Out/ui.Err to io.Discard for the duration of fn.
// The MCP transport writes JSON-RPC frames straight to os.Stdout, so any of
// the reused runXxx helpers printing human/agent-mode status lines to
// ui.Out (which defaults to os.Stdout) would corrupt the protocol stream.
func withSilentUI(fn func() error) error {
	oldOut, oldErr := ui.Out, ui.Err
	ui.Out, ui.Err = io.Discard, io.Discard
	defer func() { ui.Out, ui.Err = oldOut, oldErr }()
	return fn()
}

// mcpTools builds the tool registry for the MCP server rooted at repoRoot.
// One server instance serves exactly one project for its whole session.
func mcpTools(repoRoot string) []mcp.Tool {
	return []mcp.Tool{
		{
			Name:        "cifra_status",
			Description: "Show vault health: initialized, recipients, secrets, git hook, Privacy Shield patterns.",
			InputSchema: mcp.ObjectSchema(nil, nil),
			Handler:     func(json.RawMessage) (interface{}, error) { return computeStatus(repoRoot), nil },
		},
		{
			Name:        "cifra_list",
			Description: "List the name, kind, and algorithm of every secret in the vault (no values).",
			InputSchema: mcp.ObjectSchema(nil, nil),
			Handler:     func(json.RawMessage) (interface{}, error) { return mcpList(repoRoot) },
		},
		{
			Name:        "cifra_rotate",
			Description: "Re-seal an existing secret with a fresh data key for all current recipients (true revocation).",
			InputSchema: mcp.ObjectSchema(map[string]mcp.Property{
				"name": {Type: "string", Description: "Name of the existing secret to rotate"},
			}, []string{"name"}),
			Handler: func(args json.RawMessage) (interface{}, error) { return mcpRotate(repoRoot, args) },
		},
		{
			Name: "cifra_run",
			Description: "Decrypt env secrets into memory and run a command with them injected. " +
				"0 bytes written to disk. Returns exit code and captured stdout/stderr.",
			InputSchema: mcp.ObjectSchema(map[string]mcp.Property{
				"command": {Type: "array", Items: "string", Description: "Command and arguments, e.g. [\"npm\",\"test\"]"},
				"only":    {Type: "array", Items: "string", Description: "Inject only these keys (default: all)"},
				"except":  {Type: "array", Items: "string", Description: "Inject all keys except these"},
			}, []string{"command"}),
			Handler: func(args json.RawMessage) (interface{}, error) { return mcpRun(repoRoot, args) },
		},
		{
			Name: "cifra_protect",
			Description: "Manage AI-protected paths: add/list/remove a glob pattern, or encrypt a file " +
				"into the vault and delete its plaintext from disk.",
			InputSchema: mcp.ObjectSchema(map[string]mcp.Property{
				"action":  {Type: "string", Description: "One of: add, list, remove, encrypt"},
				"pattern": {Type: "string", Description: "Path or glob (required for add/remove)"},
				"file":    {Type: "string", Description: "File path (required for encrypt)"},
			}, []string{"action"}),
			Handler: func(args json.RawMessage) (interface{}, error) { return mcpProtect(repoRoot, args) },
		},
		{
			Name:        "cifra_push",
			Description: "Commit and push the encrypted vault to the Git remote. Re-wraps entries if the recipient set changed.",
			InputSchema: mcp.ObjectSchema(nil, nil),
			Handler:     func(json.RawMessage) (interface{}, error) { return mcpPush(repoRoot) },
		},
		{
			Name:        "cifra_pull",
			Description: "Fetch and merge the encrypted vault from the Git remote; reports added/removed/rotated secrets.",
			InputSchema: mcp.ObjectSchema(nil, nil),
			Handler:     func(json.RawMessage) (interface{}, error) { return mcpPull(repoRoot) },
		},
	}
}

// --- cifra_status / cifra_list -----------------------------------------

func mcpList(repoRoot string) (interface{}, error) {
	if !vault.IsInitialized(repoRoot) {
		return nil, fmt.Errorf("vault not initialized — run `cifra init` first")
	}
	return listEntries(repoRoot)
}

// --- cifra_rotate ----------------------------------------------------------

type entrySummary struct {
	OK         bool   `json:"ok"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Algorithm  string `json:"algorithm"`
	Recipients int    `json:"recipients"`
	UpdatedAt  string `json:"updated_at"`
}

// entrySummaryFor reloads the store and reports metadata for name — never
// the decrypted value — after a mutating operation has completed.
func entrySummaryFor(repoRoot, name string) (interface{}, error) {
	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	for _, e := range store.Entries {
		if e.Name != name {
			continue
		}
		return entrySummary{
			OK:         true,
			Name:       e.Name,
			Kind:       string(e.Kind),
			Algorithm:  string(e.Algorithm),
			Recipients: len(e.Recipients),
			UpdatedAt:  e.UpdatedAt.Format(time.RFC3339),
		}, nil
	}
	return nil, fmt.Errorf("entry %q not found after operation", name)
}

func mcpRotate(repoRoot string, raw json.RawMessage) (interface{}, error) {
	var a struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if a.Name == "" {
		return nil, fmt.Errorf("name must not be empty")
	}
	kc, err := openKeychainForMCP()
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}
	if err := withSilentUI(func() error {
		return runRotate(repoRoot, a.Name, kc)
	}); err != nil {
		return nil, err
	}
	return entrySummaryFor(repoRoot, a.Name)
}

// --- cifra_run ------------------------------------------------------------

type runResult struct {
	OK       bool   `json:"ok"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func mcpRun(repoRoot string, raw json.RawMessage) (interface{}, error) {
	var a struct {
		Command []string `json:"command"`
		Only    []string `json:"only,omitempty"`
		Except  []string `json:"except,omitempty"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if len(a.Command) == 0 {
		return nil, fmt.Errorf("command must not be empty")
	}
	if len(a.Only) > 0 && len(a.Except) > 0 {
		return nil, fmt.Errorf("only and except are mutually exclusive")
	}
	if !vault.IsInitialized(repoRoot) {
		return nil, fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	kc, err := openKeychainForMCP()
	if err != nil {
		return nil, fmt.Errorf("open keychain: %w", err)
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	envEntries := selectEnvEntries(store, runFilter{only: a.Only, except: a.Except})

	priv, _, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return nil, err
	}
	defer clear(priv[:])

	extraEnv, plaintexts, err := decryptEnvEntries(envEntries, priv)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, pt := range plaintexts {
			clear(pt)
		}
	}()

	// Deliberately not wired to os.Stdout/os.Stderr (unlike the interactive
	// `cifra run`): those file descriptors carry this server's own
	// JSON-RPC responses, so the child's output is captured instead and
	// returned as part of the tool result.
	cmd := exec.Command(a.Command[0], a.Command[1:]...) //nolint:gosec // structured, agent-supplied command is intentional
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return nil, fmt.Errorf("run %q: %w", a.Command[0], runErr)
		}
		exitCode = exitErr.ExitCode()
	}

	return runResult{OK: true, ExitCode: exitCode, Stdout: stdout.String(), Stderr: stderr.String()}, nil
}

// --- cifra_protect ---------------------------------------------------------

func mcpProtect(repoRoot string, raw json.RawMessage) (interface{}, error) {
	var a struct {
		Action  string `json:"action"`
		Pattern string `json:"pattern"`
		File    string `json:"file"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	switch a.Action {
	case "list":
		if !vault.IsInitialized(repoRoot) {
			return nil, fmt.Errorf("vault not initialized — run `cifra init` first")
		}
		patterns, err := protect.LoadPatterns(repoRoot)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "patterns": patterns}, nil
	case "add":
		if a.Pattern == "" {
			return nil, fmt.Errorf("pattern must not be empty")
		}
		if err := withSilentUI(func() error { return runProtectAdd(repoRoot, a.Pattern) }); err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "pattern": a.Pattern}, nil
	case "remove":
		if a.Pattern == "" {
			return nil, fmt.Errorf("pattern must not be empty")
		}
		if err := withSilentUI(func() error { return runProtectRemove(repoRoot, a.Pattern) }); err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "pattern": a.Pattern}, nil
	case "encrypt":
		if a.File == "" {
			return nil, fmt.Errorf("file must not be empty")
		}
		kc, err := openKeychainForMCP()
		if err != nil {
			return nil, fmt.Errorf("open keychain: %w", err)
		}
		if err := withSilentUI(func() error { return runProtectEncrypt(repoRoot, a.File, kc) }); err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "file": a.File}, nil
	default:
		return nil, fmt.Errorf("unknown action %q — must be add, list, remove, or encrypt", a.Action)
	}
}

// --- cifra_push / cifra_pull ---------------------------------------------

func mcpPush(repoRoot string) (interface{}, error) {
	if err := withSilentUI(func() error { return runPush(repoRoot) }); err != nil {
		return nil, err
	}
	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return nil, err
	}
	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	hash, _ := git.HeadHash(repoRoot)
	return map[string]interface{}{
		"ok":         true,
		"recipients": len(recipients),
		"secrets":    len(store.Entries),
		"commit":     hash,
	}, nil
}

func mcpPull(repoRoot string) (interface{}, error) {
	before, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	if err := withSilentUI(func() error { return runPull(repoRoot) }); err != nil {
		return nil, err
	}
	after, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	changes := vault.DiffStores(before, after)
	return map[string]interface{}{
		"ok":      true,
		"added":   changes.Added,
		"removed": changes.Removed,
		"rotated": changes.Rotated,
	}, nil
}
