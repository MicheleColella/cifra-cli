package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

var (
	Out io.Writer = os.Stdout
	Err io.Writer = os.Stderr
)

// AgentMode switches all output to structured JSON (set via --agent-safe or CLAUDE_CODE=1).
// When true: human-readable text and ANSI colors are suppressed; every status message
// is emitted as {"ok":true,"data":"..."} on Out or {"ok":false,"error":"..."} on Err.
var AgentMode bool

var colorEnabled = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

func OK(msg string) {
	if AgentMode {
		writeJSON(Out, map[string]interface{}{"ok": true, "data": msg})
		return
	}
	_, _ = fmt.Fprintln(Out, colorize(ansiGreen, "✓")+" "+msg)
}

func Fail(msg string) {
	if AgentMode {
		writeJSON(Err, map[string]interface{}{"ok": false, "error": msg})
		return
	}
	_, _ = fmt.Fprintln(Err, colorize(ansiRed, "✗")+" "+msg)
}

func Info(msg string) {
	if AgentMode {
		writeJSON(Out, map[string]interface{}{"ok": true, "data": msg})
		return
	}
	_, _ = fmt.Fprintln(Out, colorize(ansiDim, "→")+" "+msg)
}

func Warn(msg string) {
	if AgentMode {
		writeJSON(Err, map[string]interface{}{"ok": true, "warning": msg})
		return
	}
	_, _ = fmt.Fprintln(Out, colorize(ansiYellow, "!")+" "+msg)
}

func Header(msg string) {
	if AgentMode {
		return // suppress decorative headers in agent mode
	}
	_, _ = fmt.Fprintln(Out, colorize(ansiBold, msg))
}

// JSONResult writes structured data to Out as {"ok":true,"data":<payload>}.
// Use this in commands that need to emit machine-readable output in agent mode.
func JSONResult(payload interface{}) {
	b, _ := json.Marshal(payload)
	_, _ = fmt.Fprintf(Out, `{"ok":true,"data":%s}`+"\n", b)
}

// JSONError writes a structured error to Err as {"ok":false,"error":"..."}.
func JSONError(msg string) {
	writeJSON(Err, map[string]interface{}{"ok": false, "error": msg})
}

func NotImplemented(name string) {
	Fail(name + ": not implemented yet")
}

func writeJSON(w io.Writer, v interface{}) {
	b, _ := json.Marshal(v)
	_, _ = fmt.Fprintln(w, string(b))
}
