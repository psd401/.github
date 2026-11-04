#!/usr/bin/env bash
# ABOUTME: Installs the locked Claude Code CLI and runs `claude plugin validate` on a marketplace checkout.
# ABOUTME: Usage: validate-marketplace.sh <tools/claude-code dir> <marketplace dir>; exits non-zero if validation fails.
set -euo pipefail

tool_dir=$(cd "$1" && pwd)
marketplace=$2

# Locked install (tools/claude-code/package-lock.json), integrity-
# checked; the CLI ships as prebuilt optional packages, no scripts.
(cd "$tool_dir" && npm ci --ignore-scripts --no-audit --no-fund)
# Without its postinstall the package's `claude` bin is a stub that refuses to run;
# cli-wrapper.cjs runs the platform package's binary from the same locked install.
cli="$tool_dir/node_modules/@anthropic-ai/claude-code/cli-wrapper.cjs"
cd "$marketplace" && node "$cli" plugin validate .
