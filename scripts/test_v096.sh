#!/usr/bin/env bash
# Integration test for v0.9.6 — Security Hardening & Coverage. The bulk of
# this version (internal/secmem memory locking, fsync durability in
# vault.SaveStore, nonce-reuse guards, red-team/fuzz/snapshot test suites) is
# internal hardening with no new CLI surface to exercise from a shell script —
# it's covered by `go test ./...`. The one new user-facing command is
# `envault key reseal`, tested here end to end against the real OS keychain.
set -uo pipefail

ENVAULT=$(realpath "${1:-./envault}")
PASS=0
FAIL=0

TEST_DIR=$(mktemp -d)
KEY_ID="test-reseal-$$@example.com"
trap '"$ENVAULT" uninstall --keys >/dev/null 2>&1; rm -rf "$TEST_DIR"' EXIT

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

cd "$TEST_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test"
"$ENVAULT" init >/dev/null 2>&1 && pass "envault init" || fail "envault init"

export ENVAULT_PASSPHRASE="test-passphrase-123"
"$ENVAULT" key new --id "$KEY_ID" >/dev/null 2>&1 && pass "key new" || fail "key new"

pubkey_before=$("$ENVAULT" key export --id "$KEY_ID" --public 2>/dev/null)
if [ -n "$pubkey_before" ]; then
  pass "key export before reseal returns a public key"
else
  fail "key export before reseal (empty output)"
fi

echo "bar123" | "$ENVAULT" add FOO >/dev/null 2>&1 && pass "envault add before reseal" || fail "envault add before reseal"

# --- reseal with the same ENVAULT_PASSPHRASE (non-interactive CI path; a real
# passphrase change is an interactive-only UX, not automatable here — see
# the Claude Code hook note in .claude/rules/integration-testing.md for the
# same category of limitation) ---
"$ENVAULT" key reseal --id "$KEY_ID" >/dev/null 2>&1 && pass "key reseal" || fail "key reseal"

pubkey_after=$("$ENVAULT" key export --id "$KEY_ID" --public 2>/dev/null)
if [ "$pubkey_before" = "$pubkey_after" ] && [ -n "$pubkey_after" ]; then
  pass "resealed key material is unchanged (same public key)"
else
  fail "resealed public key mismatch (before: $pubkey_before, after: $pubkey_after)"
fi

out=$("$ENVAULT" cat FOO 2>&1)
if echo "$out" | grep -q "bar123"; then
  pass "existing secret still decrypts correctly after reseal"
else
  fail "cat after reseal (got: $out)"
fi

out=$("$ENVAULT" key reseal --id "nobody-$$-does-not-exist@example.com" 2>&1)
if [ $? -ne 0 ]; then
  pass "key reseal on a nonexistent id fails"
else
  fail "key reseal on a nonexistent id should have failed (got: $out)"
fi

# --- vault write path still works end-to-end (fsync durability change in
# vault.SaveStore is internal, but a broken implementation would break every
# write) ---
echo "baz456" | "$ENVAULT" add BAR >/dev/null 2>&1 && pass "envault add after reseal" || fail "envault add after reseal"
out=$("$ENVAULT" list 2>&1)
if echo "$out" | grep -q "BAR" && echo "$out" | grep -q "FOO"; then
  pass "envault list shows both secrets after reseal"
else
  fail "envault list after reseal (got: $out)"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
