#!/usr/bin/env bash
# ABOUTME: Tests for validate-marketplace.sh, run against the real locked Claude Code CLI in tools/claude-code.
# ABOUTME: Run with `bash scripts/validate-marketplace.test.sh`; needs Node.js and npm; exits non-zero if any test fails.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/validate-marketplace.sh"
TOOL="$(cd "$(dirname "$0")/../tools/claude-code" && pwd)"
failures=0

check() {
  local label=$1; shift
  if ! "$@"; then
    echo "  FAIL: $label"
    failures=$((failures + 1))
  fi
}

run_test() {
  local name=$1
  local work
  work=$(mktemp -d)
  echo "$name"
  pushd "$work" > /dev/null || exit 1
  "$name" || failures=$((failures + 1))
  popd > /dev/null || exit 1
  rm -rf "$work"
}

# A copy of the locked tool, so the install never lands in the checkout.
make_tool() {
  mkdir tool
  cp "$TOOL/package.json" "$TOOL/package-lock.json" tool/
}

make_marketplace() {
  mkdir -p marketplace/.claude-plugin marketplace/plugins/example/.claude-plugin
  cat > marketplace/.claude-plugin/marketplace.json <<'JSON'
{"name": "example-marketplace", "description": "Example", "owner": {"name": "Example"},
 "plugins": [{"name": "example", "source": "./plugins/example", "description": "Example", "category": "productivity"}]}
JSON
  echo '{"name": "example", "version": "1.0.0", "description": "Example", "author": {"name": "Example"}}' \
    > marketplace/plugins/example/.claude-plugin/plugin.json
}

test_a_valid_marketplace_passes() {
  make_tool
  make_marketplace
  local out
  if ! out=$(bash "$SCRIPT" tool marketplace 2>&1); then echo "$out"; echo "  FAIL: script failed"; return 1; fi
  check "reports validation passed" grep -q "Validation passed" <<<"$out"
}

test_an_invalid_marketplace_is_refused() {
  make_tool
  make_marketplace
  echo '{"name": "example-marketplace", "owner": {"name": "Example"}, "plugins": "not a list"}' \
    > marketplace/.claude-plugin/marketplace.json
  local out
  if out=$(bash "$SCRIPT" tool marketplace 2>&1); then echo "  FAIL: script succeeded"; return 1; fi
  check "names the invalid field" grep -q "plugins: Invalid input" <<<"$out"
}

for t in $(declare -F | awk '{print $3}' | grep '^test_'); do
  run_test "$t"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all passed"
