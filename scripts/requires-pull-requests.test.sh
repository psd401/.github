#!/usr/bin/env bash
# ABOUTME: Tests for requires-pull-requests.sh, fed branch-rule lists shaped like GitHub's API returns.
# ABOUTME: Run with `bash scripts/requires-pull-requests.test.sh`; exits non-zero if any test fails.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/requires-pull-requests.sh"
REPO=psd401/example-plugin-repo
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

# GET /repos/{owner}/{repo}/rules/branches/{branch}, trimmed to the fields that matter.
BASELINE='{"type": "deletion", "ruleset_source_type": "Organization"}, {"type": "non_fast_forward", "ruleset_source_type": "Organization"}'
PULL_REQUEST='{"type": "pull_request", "ruleset_source_type": "Repository", "parameters": {"required_approving_review_count": 0}}'

test_a_branch_that_requires_pull_requests_passes() {
  echo "[$BASELINE, $PULL_REQUEST]" > rules.json
  check "passes" bash "$SCRIPT" rules.json "$REPO" main
}

test_a_branch_with_only_the_baseline_rules_is_refused() {
  echo "[$BASELINE]" > rules.json
  local err
  if err=$(bash "$SCRIPT" rules.json "$REPO" main 2>&1); then echo "  FAIL: script succeeded"; return 1; fi
  check "names the repo and branch" grep -q "$REPO.*main" <<<"$err"
}

test_a_branch_with_no_rules_is_refused() {
  echo "[]" > rules.json
  if bash "$SCRIPT" rules.json "$REPO" main > /dev/null 2>&1; then echo "  FAIL: script succeeded"; return 1; fi
}

test_an_api_error_is_refused() {
  echo '{"message": "Not Found", "status": "404"}' > rules.json
  if bash "$SCRIPT" rules.json "$REPO" main > /dev/null 2>&1; then echo "  FAIL: script succeeded"; return 1; fi
}

test_a_response_that_is_not_json_is_refused() {
  echo 'not json' > rules.json
  if bash "$SCRIPT" rules.json "$REPO" main > /dev/null 2>&1; then echo "  FAIL: script succeeded"; return 1; fi
}

for t in $(declare -F | awk '{print $3}' | grep '^test_'); do
  run_test "$t"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all passed"
