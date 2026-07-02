package ui

import (
	"bytes"
	"strings"
	"testing"
)

func captureOut(fn func()) string {
	orig := Out
	var buf bytes.Buffer
	Out = &buf
	fn()
	Out = orig
	return buf.String()
}

func captureErr(fn func()) string {
	orig := Err
	var buf bytes.Buffer
	Err = &buf
	fn()
	Err = orig
	return buf.String()
}

func TestOK(t *testing.T) {
	got := captureOut(func() { OK("all good") })
	if !strings.Contains(got, "✓") || !strings.Contains(got, "all good") {
		t.Errorf("OK() = %q, want ✓ and message", got)
	}
}

func TestFail(t *testing.T) {
	got := captureErr(func() { Fail("broken") })
	if !strings.Contains(got, "✗") || !strings.Contains(got, "broken") {
		t.Errorf("Fail() = %q, want ✗ and message", got)
	}
}

func TestInfo(t *testing.T) {
	got := captureOut(func() { Info("hint") })
	if !strings.Contains(got, "→") || !strings.Contains(got, "hint") {
		t.Errorf("Info() = %q, want → and message", got)
	}
}

func TestWarn(t *testing.T) {
	got := captureOut(func() { Warn("careful") })
	if !strings.Contains(got, "!") || !strings.Contains(got, "careful") {
		t.Errorf("Warn() = %q, want ! and message", got)
	}
}

func TestHeader(t *testing.T) {
	got := captureOut(func() { Header("Cifra") })
	if !strings.Contains(got, "Cifra") {
		t.Errorf("Header() = %q, want message", got)
	}
}

func TestNotImplemented(t *testing.T) {
	got := captureErr(func() { NotImplemented("init") })
	if !strings.Contains(got, "init") || !strings.Contains(got, "not implemented yet") {
		t.Errorf("NotImplemented() = %q", got)
	}
}

func TestColorizeDisabled(t *testing.T) {
	orig := colorEnabled
	colorEnabled = false
	t.Cleanup(func() { colorEnabled = orig })

	got := colorize(ansiGreen, "hello")
	if got != "hello" {
		t.Errorf("colorize with color disabled = %q, want plain %q", got, "hello")
	}
}

func TestColorizeEnabled(t *testing.T) {
	orig := colorEnabled
	colorEnabled = true
	t.Cleanup(func() { colorEnabled = orig })

	got := colorize(ansiGreen, "hello")
	if got == "hello" || !strings.Contains(got, "hello") {
		t.Errorf("colorize with color enabled = %q, want ANSI-wrapped string containing 'hello'", got)
	}
	if !strings.Contains(got, ansiReset) {
		t.Errorf("colorize with color enabled = %q, missing reset code", got)
	}
}

func TestOKNoColorInOutput(t *testing.T) {
	orig := colorEnabled
	colorEnabled = false
	t.Cleanup(func() { colorEnabled = orig })

	got := captureOut(func() { OK("plain") })
	if strings.Contains(got, ansiGreen) {
		t.Errorf("OK() with color disabled should not contain ANSI codes, got %q", got)
	}
	if !strings.Contains(got, "✓") || !strings.Contains(got, "plain") {
		t.Errorf("OK() with color disabled = %q, want ✓ and message", got)
	}
}
