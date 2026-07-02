#!/usr/bin/env bash
# Integration test for v0.8.3 — Agent-Native CLI & Natural Language Interface
# Tests: --json flag, cifra status, cifra agent-check
set -uo pipefail

CIFRA=$(realpath "${1:-./cifra}")
PASS=0
FAIL=0
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# Setup: fresh vault with one recipient (memstore — no real keychain needed)
cd "$TEST_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test"

# Init vault (no key needed for status/agent-check)
"$CIFRA" init 2>/dev/null && pass "cifra init" || fail "cifra init"

# --- --json flag ---
out=$("$CIFRA" --json list 2>/dev/null)
if echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True" 2>/dev/null; then
  pass "--json flag produces valid JSON"
else
  fail "--json flag produces valid JSON (got: $out)"
fi

# --- cifra status (human mode) ---
out=$("$CIFRA" status 2>/dev/null)
if echo "$out" | grep -q "initialized"; then
  pass "cifra status shows initialized"
else
  fail "cifra status shows initialized (got: $out)"
fi

# --- cifra status (JSON mode) ---
out=$("$CIFRA" status --json 2>/dev/null)
if echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True; assert 'initialized' in d['data']" 2>/dev/null; then
  pass "cifra status --json produces valid JSON with initialized field"
else
  fail "cifra status --json produces valid JSON with initialized field (got: $out)"
fi

# initialized=true in status output
if echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['data']['initialized']==True" 2>/dev/null; then
  pass "cifra status reports initialized=true"
else
  fail "cifra status reports initialized=true (got: $out)"
fi

# --- cifra agent-check (JSON mode, not ready) ---
out=$("$CIFRA" agent-check --json 2>/dev/null || true)
if echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True; assert 'ready' in d['data']" 2>/dev/null; then
  pass "cifra agent-check --json produces JSON with ready field"
else
  fail "cifra agent-check --json produces JSON with ready field (got: $out)"
fi

# agent-check exits non-zero when not configured
if "$CIFRA" agent-check 2>/dev/null; then
  fail "cifra agent-check should exit non-zero when not configured"
else
  pass "cifra agent-check exits non-zero when not configured"
fi

# --- cifra agent-check (human mode, error output) ---
out=$("$CIFRA" agent-check 2>/dev/null || true)
if echo "$out" | grep -q "Claude Code hook\|Privacy Shield\|Output masking"; then
  pass "cifra agent-check human mode shows check labels"
else
  fail "cifra agent-check human mode shows check labels (got: $out)"
fi

# --- uninitialized vault: status still works ---
UNINIT_DIR=$(mktemp -d)
cd "$UNINIT_DIR"
git init -q
out=$("$CIFRA" status 2>/dev/null)
if echo "$out" | grep -q "✗\|initialized"; then
  pass "cifra status works in uninitialized repo"
else
  fail "cifra status works in uninitialized repo (got: $out)"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
