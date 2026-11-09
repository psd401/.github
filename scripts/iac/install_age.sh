#!/usr/bin/env bash
# ABOUTME: Installs age v1.3.2 from its GitHub release after checking the tarball against
# ABOUTME: a pinned SHA-256. Prints the bin directory and appends it to GITHUB_PATH.
# Usage: install_age.sh [DEST]   (default: $RUNNER_TEMP/age-bin)
# Digests are GitHub's release asset digests for v1.3.2 (published 2026-08-29),
# re-checked against a local download on 2026-10-23.
set -euo pipefail

version="v1.3.2"
base="${AGE_BASE_URL:-https://github.com/FiloSottile/age/releases/download/${version}}"
dest="${1:-${RUNNER_TEMP:?set RUNNER_TEMP or pass DEST}/age-bin}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset="age-${version}-linux-amd64.tar.gz"
    want="cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10" ;;
  Darwin-arm64)
    asset="age-${version}-darwin-arm64.tar.gz"
    want="e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5" ;;
  *)
    echo "install_age.sh: no pinned age build for $(uname -s)-$(uname -m)" >&2
    exit 1 ;;
esac

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/age-dl.XXXXXX")"
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset"
if command -v sha256sum >/dev/null; then
  got="$(sha256sum "$work/$asset" | cut -d' ' -f1)"
else
  got="$(shasum -a 256 "$work/$asset" | cut -d' ' -f1)"
fi
if [ "$got" != "$want" ]; then
  echo "install_age.sh: SHA-256 mismatch for $asset (got $got, want $want)" >&2
  exit 1
fi

tar -xzf "$work/$asset" -C "$work"
mkdir -p "$dest"
install -m 0755 "$work/age/age" "$work/age/age-keygen" "$dest/"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dest" >> "$GITHUB_PATH"
fi
echo "$dest"
