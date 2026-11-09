#!/usr/bin/env bash
# ABOUTME: Installs conftest v0.71.0 from its GitHub release after checking the tarball against
# ABOUTME: a pinned SHA-256. Prints the bin directory and appends it to GITHUB_PATH.
# Usage: install_conftest.sh [DEST]   (default: $RUNNER_TEMP/conftest-bin)
# v0.71.0 is the version reusable-iac-checks.yml and reusable-onprem-checks.yml
# install. Digests are GitHub's release asset digests for v0.71.0 (published
# 2026-09-30), which match the release's checksums.txt (both read 2026-10-23).
set -euo pipefail

version="0.71.0"
base="${CONFTEST_BASE_URL:-https://github.com/open-policy-agent/conftest/releases/download/v${version}}"
dest="${1:-${RUNNER_TEMP:?set RUNNER_TEMP or pass DEST}/conftest-bin}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset="conftest_${version}_Linux_x86_64.tar.gz"
    want="765dfefdf0730693d7541ea0147e10d530a54ed257bbfec055ff34c837ffdf72" ;;
  Darwin-arm64)
    asset="conftest_${version}_Darwin_arm64.tar.gz"
    want="78051b6ef0422082ba237f0df10a636737878941927880a68893469663b9e724" ;;
  *)
    echo "install_conftest.sh: no pinned conftest build for $(uname -s)-$(uname -m)" >&2
    exit 1 ;;
esac

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/conftest-dl.XXXXXX")"
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset"
if command -v sha256sum >/dev/null; then
  got="$(sha256sum "$work/$asset" | cut -d' ' -f1)"
else
  got="$(shasum -a 256 "$work/$asset" | cut -d' ' -f1)"
fi
if [ "$got" != "$want" ]; then
  echo "install_conftest.sh: SHA-256 mismatch for $asset (got $got, want $want)" >&2
  exit 1
fi

tar -xzf "$work/$asset" -C "$work" conftest
mkdir -p "$dest"
install -m 0755 "$work/conftest" "$dest/"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dest" >> "$GITHUB_PATH"
fi
echo "$dest"
