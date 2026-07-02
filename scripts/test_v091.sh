#!/usr/bin/env bash
# Integration test for v0.9.1 — Clean Uninstall & Doctor
# Tests: cifra doctor (human + JSON, remote redaction), cifra uninstall (idempotent).
set -uo pipefail

CIFRA=$(realpath "${1:-./cifra}")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PASS=0
FAIL=0
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

cd "$TEST_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test"
# Origin with an embedded credential — doctor must redact it.
git remote add origin "https://user:supersecret@github.com/me/repo.git"

"$CIFRA" init >/dev/null 2>&1 && pass "cifra init" || fail "cifra init"

# --- doctor (human mode) ---
out=$("$CIFRA" doctor 2>/dev/null)
if echo "$out" | grep -q "Keychain backend"; then
  pass "cifra doctor shows keychain backend"
else
  fail "cifra doctor shows keychain backend (got: $out)"
fi

# --- doctor redacts remote credentials ---
if echo "$out" | grep -q "supersecret"; then
  fail "cifra doctor leaked the remote credential"
else
  pass "cifra doctor redacts remote credential"
fi

# --- doctor (JSON mode) ---
out=$("$CIFRA" doctor --json 2>/dev/null)
if echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True; assert 'binary' in d['data']; assert '***' in d['data']['git_remote']" 2>/dev/null; then
  pass "cifra doctor --json: valid JSON, binary path, redacted remote"
else
  fail "cifra doctor --json (got: $out)"
fi

# --- install a git hook, then uninstall removes it ---
"$CIFRA" hook install --git >/dev/null 2>&1 && pass "install git hook" || fail "install git hook"
[ -f .git/hooks/pre-commit ] && pass "pre-commit hook present" || fail "pre-commit hook present"

out=$("$CIFRA" uninstall 2>/dev/null)
if echo "$out" | grep -q "Git pre-commit hook"; then
  pass "cifra uninstall removes git hook"
else
  fail "cifra uninstall removes git hook (got: $out)"
fi
if grep -q "cifra" .git/hooks/pre-commit 2>/dev/null; then
  fail "git hook still references cifra after uninstall"
else
  pass "git hook block removed"
fi
# uninstall also removes the .cifra/ vault directory (undoes init)
if [ -d .cifra ]; then
  fail ".cifra/ directory still present after uninstall"
else
  pass "cifra uninstall removes .cifra/ directory"
fi

# --- uninstall is idempotent ---
out=$("$CIFRA" uninstall 2>/dev/null)
if echo "$out" | grep -q "already clean"; then
  pass "cifra uninstall is idempotent (already clean)"
else
  fail "cifra uninstall idempotent (got: $out)"
fi

# --- install.sh --uninstall (no binary in this dir → reports none found) ---
out=$(CIFRA_INSTALL_DIR="$TEST_DIR/nowhere" sh "$SCRIPT_DIR/install.sh" --uninstall 2>/dev/null || true)
if echo "$out" | grep -q "no cifra binary found\|removed"; then
  pass "install.sh --uninstall runs"
else
  fail "install.sh --uninstall (got: $out)"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
