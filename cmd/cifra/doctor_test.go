package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/MicheleColella/cifra-cli/internal/ui"
)

func TestRedactRemote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://github.com/me/repo.git", "https://github.com/me/repo.git"},
		{"https://user:ghp_secret@github.com/me/repo.git", "https://***@github.com/me/repo.git"},
		{"git@github.com:me/repo.git", "git@github.com:me/repo.git"},
	}
	for _, c := range cases {
		if got := redactRemote(c.in); got != c.want {
			t.Errorf("redactRemote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunDoctor_AgentModeEmitsJSON(t *testing.T) {
	root := initVaultRoot(t)

	ui.AgentMode = true
	var out bytes.Buffer
	ui.Out = &out
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
		ui.AgentMode = false
	})

	if err := runDoctor(root); err != nil {
		t.Fatalf("runDoctor: %v", err)
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
}
