#!/usr/bin/env bash
# Integration test for v0.9.6 — Security Hardening & Coverage. The bulk of
# this version (internal/secmem memory locking, fsync durability in
# vault.SaveStore, nonce-reuse guards, red-team/fuzz/snapshot test suites) is
# internal hardening with no new CLI surface to exercise from a shell script —
# it's covered by `go test ./...`. The one new user-facing command is
# `cifra key reseal`, tested here end to end against the real OS keychain.
set -uo pipefail

CIFRA=$(realpath "${1:-./cifra}")
PASS=0
FAIL=0

TEST_DIR=$(mktemp -d)
KEY_ID="test-reseal-$$@example.com"
trap '"$CIFRA" uninstall --keys >/dev/null 2>&1; rm -rf "$TEST_DIR"' EXIT

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

cd "$TEST_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test"
"$CIFRA" init >/dev/null 2>&1 && pass "cifra init" || fail "cifra init"

export CIFRA_PASSPHRASE="test-passphrase-123"
"$CIFRA" key new --id "$KEY_ID" >/dev/null 2>&1 && pass "key new" || fail "key new"

pubkey_before=$("$CIFRA" key export --id "$KEY_ID" --public 2>/dev/null)
if [ -n "$pubkey_before" ]; then
  pass "key export before reseal returns a public key"
else
  fail "key export before reseal (empty output)"
fi

echo "bar123" | "$CIFRA" add FOO >/dev/null 2>&1 && pass "cifra add before reseal" || fail "cifra add before reseal"

# --- reseal with the same CIFRA_PASSPHRASE (non-interactive CI path; a real
# passphrase change is an interactive-only UX, not automatable here — see
# the Claude Code hook note in .claude/rules/integration-testing.md for the
# same category of limitation) ---
"$CIFRA" key reseal --id "$KEY_ID" >/dev/null 2>&1 && pass "key reseal" || fail "key reseal"

pubkey_after=$("$CIFRA" key export --id "$KEY_ID" --public 2>/dev/null)
if [ "$pubkey_before" = "$pubkey_after" ] && [ -n "$pubkey_after" ]; then
  pass "resealed key material is unchanged (same public key)"
else
  fail "resealed public key mismatch (before: $pubkey_before, after: $pubkey_after)"
fi

out=$("$CIFRA" cat FOO 2>&1)
if echo "$out" | grep -q "bar123"; then
  pass "existing secret still decrypts correctly after reseal"
else
  fail "cat after reseal (got: $out)"
fi

out=$("$CIFRA" key reseal --id "nobody-$$-does-not-exist@example.com" 2>&1)
if [ $? -ne 0 ]; then
  pass "key reseal on a nonexistent id fails"
else
  fail "key reseal on a nonexistent id should have failed (got: $out)"
fi

# --- vault write path still works end-to-end (fsync durability change in
# vault.SaveStore is internal, but a broken implementation would break every
# write) ---
echo "baz456" | "$CIFRA" add BAR >/dev/null 2>&1 && pass "cifra add after reseal" || fail "cifra add after reseal"
out=$("$CIFRA" list 2>&1)
if echo "$out" | grep -q "BAR" && echo "$out" | grep -q "FOO"; then
  pass "cifra list shows both secrets after reseal"
else
  fail "cifra list after reseal (got: $out)"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
