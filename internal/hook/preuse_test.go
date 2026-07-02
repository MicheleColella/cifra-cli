package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- RunHookPreuse ----------------------------------------------------------

func TestRunHookPreuse_AllowsNonSensitiveCommand(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":  "Bash",
		"tool_input": map[string]interface{}{"command": "npm install"},
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	if err := RunHookPreuse(bytes.NewReader(b), &w); err != nil {
		t.Fatalf("expected no error for non-sensitive command, got: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for allowed command, got: %s", w.String())
	}
}

func TestRunHookPreuse_BlocksCifraCat(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, cmd := range []string{
		"cifra cat DB_URL",
		"./cifra cat API_KEY",
		"cifra export",
		"/usr/local/bin/cifra cat SECRET",
	} {
		input := map[string]interface{}{
			"tool_name":  "Bash",
			"tool_input": map[string]interface{}{"command": cmd},
		}
		b, _ := json.Marshal(input)
		var w bytes.Buffer

		err := RunHookPreuse(bytes.NewReader(b), &w)
		if err == nil {
			t.Errorf("cmd %q: expected ErrBlockToolCall, got nil", cmd)
			continue
		}
		if w.Len() == 0 {
			t.Errorf("cmd %q: expected block reason written to output, got nothing", cmd)
		}
		if !strings.Contains(w.String(), "cifra run") {
			t.Errorf("cmd %q: block message should mention 'cifra run', got: %s", cmd, w.String())
		}
	}
}

func TestRunHookPreuse_AllowsCatWithForce(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":  "Bash",
		"tool_input": map[string]interface{}{"command": "cifra cat DB_URL --force"},
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	if err := RunHookPreuse(bytes.NewReader(b), &w); err != nil {
		t.Fatalf("expected no error for cat --force, got: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for cat --force, got: %s", w.String())
	}
}

func TestRunHookPreuse_NoopOutsideCifraRepo(t *testing.T) {
	dir := t.TempDir() // no .cifra/

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":  "Bash",
		"tool_input": map[string]interface{}{"command": "cifra cat DB_URL"},
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	if err := RunHookPreuse(bytes.NewReader(b), &w); err != nil {
		t.Fatalf("expected no error outside cifra repo, got: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output outside cifra repo, got: %s", w.String())
	}
}

func TestRunHookPreuse_NoopForNonBashTool(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":  "Read",
		"tool_input": map[string]interface{}{"file_path": "/etc/hosts"},
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	if err := RunHookPreuse(bytes.NewReader(b), &w); err != nil {
		t.Fatalf("expected no error for non-Bash tool, got: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for non-Bash tool, got: %s", w.String())
	}
}

func TestRunHookPreuse_InvalidJSONIsNoop(t *testing.T) {
	var w bytes.Buffer
	if err := RunHookPreuse(strings.NewReader("not json at all"), &w); err != nil {
		t.Fatalf("unexpected error on invalid JSON: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for invalid JSON input, got: %s", w.String())
	}
}

// ---- IsSensitiveCifraCmd --------------------------------------------------

func TestIsSensitiveCifraCmd(t *testing.T) {
	sensitive := []string{
		"cifra cat DB_URL",
		"./cifra cat KEY",
		"/usr/local/bin/cifra cat KEY",
		"cifra export",
		"./cifra export",
	}
	notSensitive := []string{
		"cifra cat DB_URL --force",
		"cifra list",
		"cifra run -- npm start",
		"npm install",
		"echo cifra cat",   // cifra is not a command here
		"cifra add DB_URL", // not cat/export
	}

	for _, cmd := range sensitive {
		if !IsSensitiveCifraCmd(cmd) {
			t.Errorf("expected %q to be sensitive, got false", cmd)
		}
	}
	for _, cmd := range notSensitive {
		if IsSensitiveCifraCmd(cmd) {
			t.Errorf("expected %q to NOT be sensitive, got true", cmd)
		}
	}
}

// ---- IsSensitiveCifraWriteCmd --------------------------------------------

func TestIsSensitiveCifraWriteCmd(t *testing.T) {
	sensitive := []string{
		`echo "sk-live-123" | cifra add API_KEY`,
		"./cifra add DB_URL",
		"cifra set DB_URL <<< value",
		"/usr/local/bin/cifra add KEY",
	}
	notSensitive := []string{
		`echo "sk-live-123" | cifra add API_KEY --force`,
		"cifra cat DB_URL", // read, not write — handled by IsSensitiveCifraCmd
		"cifra list",
		"cifra run -- npm start",
		"npm install",
		"echo cifra add", // cifra is not a command here
	}

	for _, cmd := range sensitive {
		if !IsSensitiveCifraWriteCmd(cmd) {
			t.Errorf("expected %q to be a sensitive write, got false", cmd)
		}
	}
	for _, cmd := range notSensitive {
		if IsSensitiveCifraWriteCmd(cmd) {
			t.Errorf("expected %q to NOT be a sensitive write, got true", cmd)
		}
	}
}

func TestRunHookPreuse_BlocksCifraAddSet(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	for _, cmd := range []string{
		`echo "sk-live-123" | cifra add API_KEY`,
		"cifra set DB_URL <<< newvalue",
	} {
		input := map[string]interface{}{
			"tool_name":  "Bash",
			"tool_input": map[string]interface{}{"command": cmd},
		}
		b, _ := json.Marshal(input)
		var w bytes.Buffer

		err := RunHookPreuse(bytes.NewReader(b), &w)
		if err == nil {
			t.Errorf("cmd %q: expected ErrBlockToolCall, got nil", cmd)
			continue
		}
		if !strings.Contains(w.String(), "own terminal") {
			t.Errorf("cmd %q: block message should direct the user to their own terminal, got: %s", cmd, w.String())
		}
	}
}

func TestRunHookPreuse_AllowsAddWithForce(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".cifra"), 0o700)

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":  "Bash",
		"tool_input": map[string]interface{}{"command": `echo "val" | cifra add KEY --force`},
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	if err := RunHookPreuse(bytes.NewReader(b), &w); err != nil {
		t.Fatalf("expected no error for add --force, got: %v", err)
	}
	if w.Len() != 0 {
		t.Errorf("expected no output for add --force, got: %s", w.String())
	}
}
