#!/bin/sh
# Cifra one-line installer.
#   curl -fsSL https://raw.githubusercontent.com/MicheleColella/cifra-cli/main/scripts/install.sh | sh
#
# Env overrides:
#   CIFRA_VERSION      tag to install (default: latest release)
#   CIFRA_INSTALL_DIR  target dir (default: /usr/local/bin, falls back to ~/.local/bin)
set -eu

REPO="MicheleColella/cifra-cli"
BINARY="cifra"

err() { echo "cifra-install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "${1:-}" = "--uninstall" ]; then
  removed=0
  for d in "${CIFRA_INSTALL_DIR:-}" /usr/local/bin "$HOME/.local/bin"; do
    [ -n "$d" ] && [ -f "$d/$BINARY" ] || continue
    if [ -w "$d" ]; then rm -f "$d/$BINARY"; else sudo rm -f "$d/$BINARY"; fi
    echo "✓ removed $d/$BINARY"
    removed=1
  done
  [ "$removed" = 1 ] || echo "no $BINARY binary found in known install dirs"
  echo "! per-repo hooks/keys: run 'cifra uninstall [--keys] [--global]' in each repo first"
  exit 0
fi

have curl || err "curl is required"
have tar || err "tar is required"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) err "unsupported OS: $os (use 'go install' or 'make install' from source)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) err "unsupported arch: $arch" ;;
esac

version="${CIFRA_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
  [ -n "$version" ] || err "could not resolve the latest release tag"
fi

ver="${version#v}"
archive="${BINARY}_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $archive ($version) ..."
curl -fsSL "$base/$archive" -o "$tmp/$archive" || err "download failed: $base/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || err "checksums download failed"

echo "Verifying checksum ..."
if have sha256sum; then sumcmd="sha256sum"; else sumcmd="shasum -a 256"; fi
( cd "$tmp" && grep " ${archive}\$" checksums.txt | $sumcmd -c - >/dev/null ) ||
  err "checksum verification failed for $archive"

tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/$BINARY" ] || err "archive did not contain a '$BINARY' binary"

dir="${CIFRA_INSTALL_DIR:-/usr/local/bin}"
if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
  if [ -z "${CIFRA_INSTALL_DIR:-}" ]; then
    dir="$HOME/.local/bin"   # fall back to a user-writable dir
    mkdir -p "$dir"
  fi
fi

if [ -w "$dir" ]; then
  install -m 755 "$tmp/$BINARY" "$dir/$BINARY"
else
  echo "Elevating with sudo to write to $dir ..."
  sudo install -m 755 "$tmp/$BINARY" "$dir/$BINARY"
fi

echo "✓ installed $BINARY $version → $dir/$BINARY"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "! $dir is not on your PATH — add it:  export PATH=\"$dir:\$PATH\"" ;;
esac
