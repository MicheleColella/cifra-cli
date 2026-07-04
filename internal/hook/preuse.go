package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MicheleColella/cifra-cli/internal/audit"
	"github.com/MicheleColella/cifra-cli/internal/protect"
)

// ErrBlockToolCall is returned by RunHookPreuse when the tool call must be
// blocked. The caller must exit non-zero so Claude Code denies the tool call —
// any text already written to the output writer is shown to Claude as the reason.
var ErrBlockToolCall = fmt.Errorf("tool call blocked by cifra hook")

// PreuseInput is the subset of the Claude Code PreToolUse hook JSON we care about.
type PreuseInput struct {
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
}

// filePathTools are tools whose primary target is a file accessible via file_path.
// NotebookEdit uses notebook_path instead — handled separately.
var filePathTools = map[string]string{
	"Read":         "file_path",
	"Write":        "file_path",
	"Edit":         "file_path",
	"MultiEdit":    "file_path",
	"NotebookEdit": "notebook_path",
}

// RunHookPreuse reads Claude Code's PreToolUse JSON from r.
//
// Blocking rules (in priority order):
//  1. Read/Write/Edit/NotebookEdit tools whose file_path matches a protected pattern.
//  2. Bash commands that reference a protected path (best-effort heuristic; full
//     adversarial coverage is in v0.8.4).
//  3. Bash commands that invoke `cifra cat` or `cifra export` without --force.
//
// Each blocked call is appended to the audit log (.cifra/ai-secure.log).
// Returns ErrBlockToolCall when a call is denied; nil otherwise.
func RunHookPreuse(r io.Reader, w io.Writer) error {
	var input PreuseInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		return nil // non-fatal: allow unchanged
	}

	wd, err := os.Getwd()
	if err != nil || !IsCifraDir(wd) {
		return nil
	}

	patterns, _ := protect.LoadPatterns(wd) // ignore error: no patterns = no blocking

	// --- File tool protection ---
	if paramKey, isFileTool := filePathTools[input.ToolName]; isFileTool {
		filePath, _ := input.ToolInput[paramKey].(string)
		if filePath != "" && len(patterns) > 0 {
			if matched, ok := protect.MatchesAny(filePath, patterns); ok {
				_ = audit.AppendEntry(wd, input.ToolName, audit.ActionBlockedPath, filePath, matched)
				_, _ = fmt.Fprintf(w,
					"[CIFRA PROTECTED: %s — file contents encrypted. Use `cifra run` to access at runtime.]\n"+
						"Pattern: %s",
					filePath, matched,
				)
				return ErrBlockToolCall
			}
		}
		return nil
	}

	// --- Bash tool ---
	if input.ToolName != "Bash" {
		return nil
	}

	cmd, _ := input.ToolInput["command"].(string)
	if cmd == "" {
		return nil
	}

	// Protected path check in Bash command.
	if len(patterns) > 0 {
		if matched, tok, ok := protect.ContainsProtectedPath(cmd, patterns); ok {
			_ = audit.AppendEntry(wd, "Bash", audit.ActionBlockedCmd, snippetOf(cmd, 120), matched)
			_, _ = fmt.Fprintf(w,
				"[CIFRA PROTECTED: %s — path matches protected pattern %q. Use `cifra run` to access at runtime.]\n"+
					"Blocked command: %s",
				tok, matched, snippetOf(cmd, 200),
			)
			return ErrBlockToolCall
		}
	}

	// cifra cat / export without --force.
	if IsSensitiveCifraCmd(cmd) {
		_, _ = fmt.Fprintln(w,
			"cifra: plaintext output blocked — secrets must not appear in the model context.\n"+
				"Use `cifra run -- <cmd>` to inject secrets in-memory into a child process.\n"+
				"If you really need the plaintext value, pass --force to override.",
		)
		return ErrBlockToolCall
	}

	// cifra add / set without --force: sealing a new value this way
	// requires the plaintext to already be embedded in the Bash command
	// (there is no interactive stdin over a tool call), which is exactly
	// the exposure this hook exists to prevent.
	if IsSensitiveCifraWriteCmd(cmd) {
		_, _ = fmt.Fprintln(w,
			"cifra: sealing a secret via Bash is blocked — the plaintext would have to be\n"+
				"embedded in this command, putting it in the model's context. Ask the user to\n"+
				"run `cifra add <KEY>` / `cifra set <KEY>` themselves in their own terminal.\n"+
				"If you really need to do this here anyway, pass --force to override.",
		)
		return ErrBlockToolCall
	}

	return nil
}

// IsSensitiveCifraCmd reports whether cmd invokes `cifra cat` or
// `cifra export` as the primary command (not as an argument to another tool)
// without the --force override flag.
func IsSensitiveCifraCmd(cmd string) bool {
	return cifraSubcommandIs(cmd, "cat", "export")
}

// IsSensitiveCifraWriteCmd reports whether cmd invokes `cifra add` or
// `cifra set` as the primary command without the --force override flag.
// Unlike a plain read, sealing a value this way requires the plaintext to
// already be embedded in the command text (no interactive stdin over a tool
// call), so it is blocked the same way as a direct plaintext read.
func IsSensitiveCifraWriteCmd(cmd string) bool {
	return cifraSubcommandIs(cmd, "add", "set")
}

// cifraSubcommandIs reports whether cmd invokes cifra with one of subs as its
// subcommand, in ANY segment of a compound shell command, without an explicit
// --force override in that same segment.
//
// This is a BEST-EFFORT early block, NOT the security boundary. It catches the
// obvious evasions — the full separator set (`|` `||` `&&` `;` `&`, newlines,
// brace groups, `$(…)`/backtick substitution — see splitShellSegments),
// `sh -c "…"` nesting, quote-split binary names, and decoy `--force` in a
// different segment. But a shell command runner can always hide the invocation
// (`env cifra cat`, `eval "cifra cat"`, `echo K | xargs cifra cat`, …), so this
// parser can be defeated. That is acceptable because it is not the last line of
// defense: the REAL guard is in-process — cat/export/add/set each refuse to run
// in agent mode without --force (runCat / blockSealInAgentMode), which no shell
// wrapper can parse around. Keep this hook honest about being best-effort;
// do not grow a wrapper denylist here (an arms race that belongs nowhere).
func cifraSubcommandIs(cmd string, subs ...string) bool {
	return cifraSubcommandInSegments(cmd, 0, subs)
}

// shellCmds are the interpreters whose `-c` argument is itself a shell command
// we must re-scan (otherwise `sh -c "cifra cat K"` hides the invocation).
var shellCmds = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
}

func cifraSubcommandInSegments(cmd string, depth int, subs []string) bool {
	if depth > 4 { // guard against pathological nesting; deep enough for real commands
		return false
	}
	for _, segment := range splitShellSegments(cmd) {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		// Remove shell quotes anywhere in a token so `"cifra`, `cat"`, and
		// even a quote-split `c"i"fra` all normalize to their real form.
		for i, f := range fields {
			fields[i] = quoteStripper.Replace(f)
		}

		// Skip leading VAR=value environment assignments (e.g. CLAUDE_CODE=1 cifra …)
		start := 0
		for start < len(fields) && strings.ContainsRune(fields[start], '=') {
			start++
		}
		if start >= len(fields) {
			continue
		}

		first := fields[start]

		// Recurse into `sh -c "<script>"` (and bash/zsh/… -c): the script
		// string is a nested command that can itself run cifra.
		if base := first[strings.LastIndex(first, "/")+1:]; shellCmds[base] {
			if inner := shellDashCScript(fields[start:]); inner != "" {
				if cifraSubcommandInSegments(inner, depth+1, subs) {
					return true
				}
			}
		}

		if first != "cifra" && !strings.HasSuffix(first, "/cifra") {
			continue
		}
		if start+1 >= len(fields) {
			continue
		}
		sub := fields[start+1]
		for _, s := range subs {
			if sub == s {
				// --force only disarms the block when it appears in the SAME
				// segment as the cifra invocation.
				if segmentHasForce(fields[start:]) {
					return false
				}
				return true
			}
		}
	}
	return false
}

func segmentHasForce(fields []string) bool {
	for _, f := range fields {
		if f == "--force" {
			return true
		}
	}
	return false
}

// shellDashCScript returns the script string passed to a shell's -c flag, with
// its tokens rejoined (quotes were already stripped by the caller). Empty if
// there is no -c argument.
func shellDashCScript(fields []string) string {
	for i, f := range fields {
		if f == "-c" && i+1 < len(fields) {
			return strings.Join(fields[i+1:], " ")
		}
	}
	return ""
}

// splitShellSegments breaks a shell command line into the segments that run as
// separate simple commands, splitting on the control operators that end one
// command and start another (`|` `||` `&&` `;` `&`, newlines) and unwrapping
// `$(…)` and backtick command substitutions. It is intentionally coarse and
// fail-closed: it over-segments rather than miss an invocation.
var quoteStripper = strings.NewReplacer("\"", "", "'", "", "`", "")

func splitShellSegments(cmd string) []string {
	repl := strings.NewReplacer(
		"&&", "\x00", "||", "\x00",
		";", "\x00", "|", "\x00", "&", "\x00",
		"\n", "\x00", "\r", "\x00",
		"$(", "\x00", ")", "\x00", "(", "\x00",
		"{", "\x00", "}", "\x00",
		"`", "\x00",
	)
	parts := strings.Split(repl.Replace(cmd), "\x00")
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			segs = append(segs, p)
		}
	}
	return segs
}

// IsCifraDir returns true when .cifra/ exists under root.
func IsCifraDir(root string) bool {
	_, err := os.Stat(root + "/.cifra")
	return err == nil
}

func snippetOf(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
