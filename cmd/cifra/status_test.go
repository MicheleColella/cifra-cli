package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRunStatus_UninitializedVault(t *testing.T) {
	root := t.TempDir()

	var out bytes.Buffer
	ui.Out = &out
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runStatus(root); err != nil {
		t.Fatalf("runStatus: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "✗") {
		t.Error("expected ✗ for uninitialized vault")
	}
}

func TestRunStatus_InitializedVault(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.Out = &bytes.Buffer{}
	t.Cleanup(func() { ui.Out = os.Stdout })

	if err := runAdd(root, "MY_KEY", []byte("val")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runStatus(root); err != nil {
		t.Fatalf("runStatus: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "1") {
		t.Errorf("expected counts in output, got: %s", got)
	}
}

func TestRunStatus_AgentModeEmitsJSON(t *testing.T) {
	root := initVaultRoot(t)
	addTestRecipient(t, root, "alice@example.com")

	ui.AgentMode = true
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	ui.Out = &bytes.Buffer{}
	if err := runAdd(root, "A", []byte("v")); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	var out bytes.Buffer
	ui.Out = &out

	if err := runStatus(root); err != nil {
		t.Fatalf("runStatus agent mode: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &envelope); err != nil {
		t.Fatalf("not valid JSON: %v — raw: %s", err, out.String())
	}
	if envelope["ok"] != true {
		t.Errorf("expected ok=true, got %v", envelope["ok"])
	}
	data, _ := envelope["data"].(map[string]interface{})
	if data["initialized"] != true {
		t.Errorf("expected initialized=true, got %v", data["initialized"])
	}
	if data["secrets"].(float64) != 1 {
		t.Errorf("expected secrets=1, got %v", data["secrets"])
	}
}
