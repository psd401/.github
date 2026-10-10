#!/usr/bin/env bash
# ABOUTME: Checks that a branch's active rules require a pull request, so nothing reaches it unreviewed by CI.
# ABOUTME: Usage: requires-pull-requests.sh <rules json> <repo> <branch>, the json from GitHub's rules/branches API.
set -euo pipefail

rules=$1 repo=$2 branch=$3

# Only rulesets show up in rules/branches; classic branch protection needs
# admin access to read, so it doesn't count here.
if jq -e 'type == "array" and any(.[]; .type == "pull_request")' "$rules" > /dev/null 2>&1; then
  exit 0
fi
echo "::error::$repo's $branch branch doesn't require a pull request. Add a ruleset on it that does (psd-dev-standards standards/06)." >&2
exit 1
