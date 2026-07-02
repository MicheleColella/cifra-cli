#!/usr/bin/env bash
# Integration test for v0.9.0 — Installer & Distribution.
# Verifies: goreleaser config validity, cross-compile snapshot, install.sh syntax,
# and that install.sh's archive-name + checksum logic agrees with goreleaser output.
#
# Usage: bash scripts/test_v090.sh
# Exit 0 = all pass. Requires goreleaser on PATH (or GOPATH/bin) for the build checks.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILED=1; }
FAILED=0

GR="$(command -v goreleaser || echo "$(go env GOPATH)/bin/goreleaser")"

echo "== install.sh syntax =="
if sh -n scripts/install.sh; then pass "install.sh parses (sh -n)"; else fail "install.sh has syntax errors"; fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck scripts/install.sh >/dev/null; then pass "shellcheck clean"; else fail "shellcheck reported issues"; fi
fi

echo "== goreleaser config =="
if [ -x "$GR" ]; then
  if "$GR" check >/dev/null 2>&1; then pass ".goreleaser.yaml valid"; else fail ".goreleaser.yaml invalid"; fi
else
  echo "  - goreleaser not found; skipping build checks (install: go install github.com/goreleaser/goreleaser/v2@latest)"
  exit $FAILED
fi

echo "== cross-compile snapshot =="
# Strip AppleDouble litter that breaks the dir parser on external/exFAT drives.
find . -name '._*' -not -path './.git/*' -delete 2>/dev/null || true
if "$GR" release --snapshot --clean --skip=sign >/tmp/gr_v090.log 2>&1; then
  pass "snapshot release built"
else
  fail "snapshot release failed (see /tmp/gr_v090.log)"; exit 1
fi
for triple in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
  if ls dist/cifra_*_"${triple}".tar.gz >/dev/null 2>&1; then pass "archive present: $triple"; else fail "missing archive: $triple"; fi
done
[ -f dist/checksums.txt ] && pass "checksums.txt present" || fail "checksums.txt missing"

echo "== install.sh naming + checksum agree with release output (host platform) =="
# Reproduce install.sh's os/arch detection.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64;; arm64|aarch64) arch=arm64;; esac
archive=$(ls dist/cifra_*_"${os}_${arch}".tar.gz 2>/dev/null | head -1)
if [ -n "$archive" ]; then
  pass "host archive found: $(basename "$archive")"
  sumcmd="sha256sum"; command -v sha256sum >/dev/null 2>&1 || sumcmd="shasum -a 256"
  if ( cd dist && grep " $(basename "$archive")\$" checksums.txt | $sumcmd -c - >/dev/null 2>&1 ); then
    pass "checksum verifies (same path install.sh uses)"
  else
    fail "checksum verification failed"
  fi
  tmp=$(mktemp -d); tar -xzf "$archive" -C "$tmp"
  if [ -x "$tmp/cifra" ] && "$tmp/cifra" --version >/dev/null 2>&1; then
    pass "extracted binary runs --version"
  else
    fail "extracted binary did not run"
  fi
  rm -rf "$tmp"
else
  echo "  - no archive for host ${os}_${arch} (non darwin/linux host); skipping extract check"
fi

echo
if [ "$FAILED" -eq 0 ]; then echo "ALL v0.9.0 CHECKS PASSED"; else echo "SOME v0.9.0 CHECKS FAILED"; fi
exit $FAILED
