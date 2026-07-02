package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/audit"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunAuditLogShow_EmptyLog(t *testing.T) {
	dir := makeVaultedDir(t)

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAuditLogShow(dir); err != nil {
		t.Fatalf("runAuditLogShow: %v", err)
	}
	if !strings.Contains(out.String(), "No audit log") {
		t.Errorf("expected 'No audit log' message, got %q", out.String())
	}
}

func TestRunAuditLogShow_PrintsEntries(t *testing.T) {
	dir := makeVaultedDir(t)
	_ = audit.AppendEntry(dir, "Read", audit.ActionBlockedPath, "config/secrets.json", "config/secrets.json")
	_ = audit.AppendEntry(dir, "Bash", audit.ActionBlockedCmd, "cat config/secrets.json", "config/secrets.json")

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAuditLogShow(dir); err != nil {
		t.Fatalf("runAuditLogShow: %v", err)
	}
	if !strings.Contains(out.String(), "blocked_path") {
		t.Errorf("expected blocked_path in output, got %q", out.String())
	}
}

func TestRunAuditLogVerify_ValidChain(t *testing.T) {
	dir := makeVaultedDir(t)
	_ = audit.AppendEntry(dir, "Read", audit.ActionBlockedPath, "file.json", "file.json")
	_ = audit.AppendEntry(dir, "Bash", audit.ActionBlockedCmd, "cat file.json", "file.json")

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	var errOut bytes.Buffer
	ui.Err = &errOut
	t.Cleanup(func() { ui.Err = os.Stderr })

	if err := runAuditLogVerify(dir); err != nil {
		t.Fatalf("runAuditLogVerify: %v", err)
	}
	if !strings.Contains(out.String(), "OK") {
		t.Errorf("expected OK in output, got %q", out.String())
	}
}

func TestRunAuditLogVerify_EmptyLog(t *testing.T) {
	dir := makeVaultedDir(t)

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAuditLogVerify(dir); err != nil {
		t.Fatalf("runAuditLogVerify on empty log: %v", err)
	}
}

func TestRunAuditLogVerify_FailsWithoutVault(t *testing.T) {
	dir := t.TempDir()

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAuditLogVerify(dir); err == nil {
		t.Error("expected error without vault")
	}
}
