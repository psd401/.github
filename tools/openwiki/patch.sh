#!/usr/bin/env bash
# Patches the locked openwiki CLI after `npm ci`. Each patch names the upstream
# bug it works around and fails the install if its anchor text is missing, so
# a version bump that changes the code stops here instead of running unpatched.
# Drop a patch once the locked version carries the upstream fix.
set -euo pipefail
dist="$1/node_modules/openwiki/dist"

patch_once() { # file, anchor, replacement
  local file="$dist/$1"
  if ! grep -qF "$2" "$file"; then
    echo "::error::openwiki patch anchor not found in $1; re-check tools/openwiki/patch.sh against the locked version"
    exit 1
  fi
  ANCHOR="$2" REPLACEMENT="$3" perl -0pi -e 's/\Q$ENV{ANCHOR}\E/$ENV{REPLACEMENT}/' "$file"
  grep -qF "$3" "$file"
}

# 1. langchain-ai/openwiki#871: when a page worker gives up on a page that did
# not exist before the run, openwiki restores the snapshot by deleting the
# page. The filesystem backend reports a missing file as "ENOENT: no such file
# or directory", which isNotFoundBackendError doesn't recognise, so the run
# dies with "Could not restore <page>: Error deleting ... ENOENT" instead of
# skipping the page (psd-dev-standards#321).
patch_once generation/repository-run.js \
  'return error === "file_not_found" || error.includes("not found");' \
  'return error === "file_not_found" || error.includes("not found") || error.includes("ENOENT");'

# 2. Visibility: --print buffers all output until the run ends and never shows
# why a page worker gave up, so a failed run logs nothing. Write each failed
# attempt and its error to stderr as it happens.
patch_once agent/repository-runner.js \
  '        skipped = outcome;' \
  '        skipped = outcome;
        process.stderr.write(`openwiki: page worker attempt ${attempt} for ${job.path} did not submit${outcome.error ? `: ${outcome.error?.stack ?? outcome.error}` : " (exited without submit_page)"}\n`);'

# 3. Visibility: 0.9.0 stops a worker after 5 submit_plan/submit_page calls
# and fails the run with only "'submit_plan' tool call limit reached", never
# saying why each submission was rejected (psd-dev-standards#321). Write each
# rejection's code and message to stderr.
patch_once agent/repository-runner.js \
  'function createSubmissionRejection(toolName, error, retry, toolCallId) {' \
  'function createSubmissionRejection(toolName, error, retry, toolCallId) {
    process.stderr.write(`openwiki: ${toolName} rejected (${error.code}): ${String(error.message).slice(0, 2000)}\n`);'

# 4. Progress: --print shows nothing until the run ends, so a run cut off by
# the job timeout can't be told apart from a hung one. Log the planned page
# count and each page's outcome as it finishes.
patch_once generation/repository-run.js \
  '    return { status: "accepted", totalPages: plan.pages.length };' \
  '    process.stderr.write(`openwiki: plan accepted: ${plan.pages.length} pages, ${plan.deletePages.length} deletions\n`);
    return { status: "accepted", totalPages: plan.pages.length };'
patch_once agent/repository-runner.js \
  '        if (outcome.status === "skipped") {' \
  '        process.stderr.write(`openwiki: page ${next.job.path} ${outcome.status}\n`);
        if (outcome.status === "skipped") {'

echo "openwiki patched: #871 ENOENT restore; page-failure, rejection and progress logging"
