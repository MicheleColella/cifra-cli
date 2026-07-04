#!/usr/bin/env bash
# Integration test for v0.9.7 — Custom Git Merge Driver
# Covers: init registers the driver (.gitattributes + .git/config), a REAL
# `git merge` auto-resolves disjoint secret adds via the driver (no conflict
# markers), the fail-closed misconfigured state + `init --upgrade` fix, and
# conflict-marker detection when secrets.enc was text-merged without the driver.
set -uo pipefail

CIFRA=$(realpath "${1:-./cifra}")
# The git merge driver invokes `cifra` by PATH name — make that resolve to the
# binary under test, not an older one already installed on the system.
export PATH="$(dirname "$CIFRA"):$PATH"
export CIFRA_PASSPHRASE="merge-driver-test-pass"
KEY_ID="merge-test-$$@example.com"

PASS=0
FAIL=0
TEST_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TEST_DIR"
  # Remove the throwaway key this test sealed into the OS keychain.
  security delete-generic-password -s cifra -a "$KEY_ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

cd "$TEST_DIR"
git init -q
git config user.email "test@example.com"
git config user.name "Test"

"$CIFRA" init >/dev/null 2>&1 && pass "cifra init" || fail "cifra init"
"$CIFRA" key new --id "$KEY_ID" >/dev/null 2>&1 && pass "key new" || fail "key new"

# --- 1. init registered the driver ---
if grep -q "merge=cifra" .gitattributes 2>/dev/null; then
  pass ".gitattributes routes secrets.enc to the driver"
else
  fail ".gitattributes missing merge=cifra"
fi
if git config --local --get merge.cifra.driver | grep -q "cifra merge"; then
  pass ".git/config defines the cifra merge driver"
else
  fail ".git/config missing merge.cifra.driver"
fi
if "$CIFRA" doctor 2>/dev/null | grep -q "Merge driver             ✓"; then
  pass "doctor reports merge driver registered"
else
  fail "doctor should show merge driver ✓"
fi

# --- 2. real git merge auto-resolves disjoint secret adds ---
git add -A && git commit -qm "init vault"
printf 'v1' | "$CIFRA" add KEY1 >/dev/null 2>&1
git add -A && git commit -qm "add KEY1"

git checkout -q -b feature
printf 'v2' | "$CIFRA" add KEY2 >/dev/null 2>&1
git add -A && git commit -qm "add KEY2"

git checkout -q master 2>/dev/null || git checkout -q main
printf 'v3' | "$CIFRA" add KEY3 >/dev/null 2>&1
git add -A && git commit -qm "add KEY3"

if git merge feature -m "merge feature" >/dev/null 2>&1; then
  pass "git merge auto-resolved via the driver (exit 0)"
else
  fail "git merge should auto-resolve disjoint secret adds"
fi
if grep -q "<<<<<<<" .cifra/secrets.enc; then
  fail "driver left conflict markers in secrets.enc"
else
  pass "no conflict markers in merged secrets.enc"
fi
listed=$("$CIFRA" list 2>/dev/null)
if echo "$listed" | grep -q KEY1 && echo "$listed" | grep -q KEY2 && echo "$listed" | grep -q KEY3; then
  pass "merged vault contains KEY1, KEY2, KEY3"
else
  fail "merged vault missing entries (got: $listed)"
fi

# --- 3. fail-closed: declared but not registered, then init --upgrade fixes it ---
git config --local --unset merge.cifra.driver
if "$CIFRA" doctor --json 2>/dev/null | grep -q '"merge_driver_warn":true'; then
  pass "doctor flags misconfigured driver (declared, not registered)"
else
  fail "doctor should flag merge_driver_warn when unregistered"
fi
"$CIFRA" init --upgrade >/dev/null 2>&1 && pass "cifra init --upgrade" || fail "cifra init --upgrade"
if "$CIFRA" doctor --json 2>/dev/null | grep -q '"merge_driver_warn":false'; then
  pass "init --upgrade cleared the misconfigured state"
else
  fail "init --upgrade should clear merge_driver_warn"
fi

# --- 4. conflict-marker detection (corruption from a text-merge) ---
cp .cifra/secrets.enc /tmp/cifra_good_$$.enc
{ echo "<<<<<<< HEAD"; cat /tmp/cifra_good_$$.enc; echo "======="; cat /tmp/cifra_good_$$.enc; echo ">>>>>>> theirs"; } > .cifra/secrets.enc
# Capture first: `cifra list` exits nonzero here, and `set -o pipefail` would
# otherwise fail the whole pipeline even when grep matches.
marker_out=$("$CIFRA" list 2>&1)
if echo "$marker_out" | grep -qi "conflict markers"; then
  pass "cifra refuses a text-merge-corrupted secrets.enc with an actionable error"
else
  fail "cifra should detect conflict markers in secrets.enc (got: $marker_out)"
fi
cp /tmp/cifra_good_$$.enc .cifra/secrets.enc
rm -f /tmp/cifra_good_$$.enc

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
