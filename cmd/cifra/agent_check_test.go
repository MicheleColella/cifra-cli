package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/protect"
	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunAgentCheck_AllMissing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CIFRA_PASSPHRASE", "")

	var out bytes.Buffer
	ui.Out = &out
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	err := runAgentCheck(root)
	if err == nil {
		t.Fatal("expected error when nothing is configured")
	}
	if !strings.Contains(err.Error(), "not fully configured") {
		t.Errorf("unexpected error: %v", err)
	}
	got := out.String()
	if strings.Count(got, "✗") < 2 {
		t.Errorf("expected at least 2 ✗ marks, got: %s", got)
	}
}

func TestRunAgentCheck_AgentModeJSON(t *testing.T) {
	root := initVaultRoot(t)
	if err := protect.AddPattern(root, "secrets/"); err != nil {
		t.Fatalf("protect.AddPattern: %v", err)
	}
	t.Setenv("CIFRA_PASSPHRASE", "test-passphrase")

	ui.AgentMode = true
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	var out bytes.Buffer
	ui.Out = &out
	ui.Err = &bytes.Buffer{}

	// Privacy Shield + output masking are both configured here, so ready=true.
	_ = runAgentCheck(root) // we check JSON output regardless of return

	raw := strings.TrimSpace(out.String())
	if raw == "" {
		t.Fatal("expected JSON output in agent mode, got empty string")
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("not valid JSON: %v — raw: %s", err, raw)
	}
	if envelope["ok"] != true {
		t.Errorf("expected ok=true, got %v", envelope["ok"])
	}
	data, _ := envelope["data"].(map[string]interface{})
	if _, ok := data["ready"]; !ok {
		t.Error("expected ready field in data")
	}
	if data["privacy_shield"] != true {
		t.Errorf("expected privacy_shield=true, got %v", data["privacy_shield"])
	}
	if data["output_masking"] != true {
		t.Errorf("expected output_masking=true, got %v", data["output_masking"])
	}
}
