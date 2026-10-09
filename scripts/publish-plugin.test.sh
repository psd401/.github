#!/usr/bin/env bash
# ABOUTME: Tests for publish-plugin.sh, run against throwaway plugin and marketplace folders.
# ABOUTME: Run with `bash scripts/publish-plugin.test.sh`; exits non-zero if any test fails.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/publish-plugin.sh"
REPO=psd401/example-plugin-repo
failures=0

# A marketplace shaped like psd-claude-plugins: metadata, one hand-maintained
# plugin, and non-ASCII text that must survive being rewritten.
make_marketplace() {
  local dir=$1
  mkdir -p "$dir/.claude-plugin" "$dir/plugins/hand-made/.claude-plugin"
  cat > "$dir/.claude-plugin/marketplace.json" <<'EOF'
{
  "name": "example-marketplace",
  "owner": {
    "name": "Example Owner"
  },
  "metadata": {
    "description": "Plugins — for testing",
    "version": "2.0.0",
    "pluginRoot": "./plugins"
  },
  "plugins": [
    {
      "name": "hand-made",
      "source": "./plugins/hand-made",
      "description": "Maintained here by hand",
      "version": "1.0.0",
      "category": "productivity",
      "keywords": [
        "example"
      ]
    }
  ]
}
EOF
  echo '{"name": "hand-made", "version": "1.0.0"}' > "$dir/plugins/hand-made/.claude-plugin/plugin.json"
}

# A plugin as it sits in its source repo.
make_plugin() {
  local dir=$1 name=$2 version=$3
  mkdir -p "$dir/.claude-plugin" "$dir/hooks"
  jq -n --arg name "$name" --arg version "$version" \
    '{name: $name, description: "Does a thing", version: $version, keywords: ["one", "two"]}' \
    > "$dir/.claude-plugin/plugin.json"
  echo "export const hook = 1" > "$dir/hooks/hook.ts"
}

set_version() {
  local file="$1/.claude-plugin/plugin.json" tmp
  tmp=$(mktemp)
  jq --arg v "$2" '.version = $v' "$file" > "$tmp" && mv "$tmp" "$file"
}

entry() {
  jq -c --arg name "$2" '.plugins[] | select(.name == $name)' "$1/.claude-plugin/marketplace.json"
}

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

test_a_new_plugin_is_copied_and_listed() {
  make_marketplace m && make_plugin p collab 1.0.0
  local before out
  before=$(cat m/.claude-plugin/marketplace.json)
  out=$(bash "$SCRIPT" p m "$REPO" productivity) || { echo "  FAIL: script exited $?"; return 1; }
  check "reports the change" grep -qx "changed=true" <<<"$out"
  check "reports the name" grep -qx "name=collab" <<<"$out"
  check "reports the version" grep -qx "version=1.0.0" <<<"$out"
  check "copies the plugin" cmp -s p/hooks/hook.ts m/plugins/collab/hooks/hook.ts
  check "records the source repo" test "$(cat m/plugins/collab/.publish-source)" = "$REPO"
  check "adds an entry after the others, fields in the marketplace's order" test "$(entry m collab)" = \
    '{"name":"collab","source":"./plugins/collab","description":"Does a thing","version":"1.0.0","category":"productivity","keywords":["one","two"]}'
  check "leaves everything else as it was" test \
    "$(jq 'del(.plugins[] | select(.name == "collab"))' m/.claude-plugin/marketplace.json)" = "$before"
}

test_a_new_plugin_without_a_category_gets_none() {
  make_marketplace m && make_plugin p collab 1.0.0
  bash "$SCRIPT" p m "$REPO" > /dev/null || { echo "  FAIL: script exited $?"; return 1; }
  check "has no category" test "$(entry m collab | jq 'has("category")')" = false
}

test_a_new_version_replaces_the_files_and_the_entry_version() {
  make_marketplace m && make_plugin p collab 1.0.0
  bash "$SCRIPT" p m "$REPO" productivity > /dev/null || { echo "  FAIL: first publish failed"; return 1; }
  rm p/hooks/hook.ts && echo "export const other = 2" > p/hooks/other.ts
  set_version p 1.1.0
  local before out
  before=$(cat m/.claude-plugin/marketplace.json)
  out=$(bash "$SCRIPT" p m "$REPO" productivity) || { echo "  FAIL: script exited $?"; return 1; }
  check "reports the change" grep -qx "changed=true" <<<"$out"
  check "adds new files" test -f m/plugins/collab/hooks/other.ts
  check "removes files the plugin no longer has" test ! -e m/plugins/collab/hooks/hook.ts
  check "keeps the source record" test "$(cat m/plugins/collab/.publish-source)" = "$REPO"
  check "changes only the entry's version" test \
    "$(jq '(.plugins[] | select(.name == "collab") | .version) = "1.0.0"' m/.claude-plugin/marketplace.json)" = "$before"
  check "the entry has the new version" test "$(entry m collab | jq -r .version)" = 1.1.0
}

test_an_unchanged_plugin_changes_nothing() {
  make_marketplace m && make_plugin p collab 1.0.0
  bash "$SCRIPT" p m "$REPO" > /dev/null || { echo "  FAIL: first publish failed"; return 1; }
  local snapshot out
  snapshot=$(mktemp -d) && cp -R m "$snapshot/"
  out=$(bash "$SCRIPT" p m "$REPO") || { echo "  FAIL: script exited $?"; return 1; }
  check "reports no change" grep -qx "changed=false" <<<"$out"
  check "touches no file" diff -r "$snapshot/m" m
}

test_a_change_without_a_new_version_is_refused() {
  make_marketplace m && make_plugin p collab 1.0.0
  bash "$SCRIPT" p m "$REPO" > /dev/null || { echo "  FAIL: first publish failed"; return 1; }
  echo "export const other = 2" > p/hooks/other.ts
  local snapshot err
  snapshot=$(mktemp -d) && cp -R m "$snapshot/"
  if err=$(bash "$SCRIPT" p m "$REPO" 2>&1 >/dev/null); then echo "  FAIL: script succeeded"; return 1; fi
  check "says to change the version" grep -q "still version 1.0.0" <<<"$err"
  check "touches no file" diff -r "$snapshot/m" m
}

test_a_plugin_without_a_version_is_refused() {
  make_marketplace m && make_plugin p collab 1.0.0
  jq 'del(.version)' p/.claude-plugin/plugin.json > tmp.json && mv tmp.json p/.claude-plugin/plugin.json
  local err
  if err=$(bash "$SCRIPT" p m "$REPO" 2>&1 >/dev/null); then echo "  FAIL: script succeeded"; return 1; fi
  check "says a version is needed" grep -q "needs a version" <<<"$err"
  check "copies nothing" test ! -e m/plugins/collab
}

test_a_version_that_is_not_a_plain_version_string_is_refused() {
  local version
  for version in $'1.0.0\nname=other' "1.0 .0" "v1/2"; do
    rm -rf m p && make_marketplace m && make_plugin p collab "$version"
    if bash "$SCRIPT" p m "$REPO" > /dev/null 2>&1; then echo "  FAIL: accepted version '$version'"; return 1; fi
  done
  check "copies nothing" test ! -e m/plugins/collab
}

test_a_name_that_is_not_a_plain_slug_is_refused() {
  local name
  for name in "../hand-made" "Collab" "col lab" "" "-collab"; do
    rm -rf m p && make_marketplace m && make_plugin p "$name" 1.0.0
    if bash "$SCRIPT" p m "$REPO" > /dev/null 2>&1; then echo "  FAIL: accepted name '$name'"; return 1; fi
  done
  check "leaves the hand-made plugin alone" test -f m/plugins/hand-made/.claude-plugin/plugin.json
}

test_a_plugin_maintained_in_the_marketplace_is_never_overwritten() {
  make_marketplace m && make_plugin p hand-made 9.0.0
  local snapshot err
  snapshot=$(mktemp -d) && cp -R m "$snapshot/"
  if err=$(bash "$SCRIPT" p m "$REPO" 2>&1 >/dev/null); then echo "  FAIL: script succeeded"; return 1; fi
  check "says whose it is" grep -q "isn't published from $REPO" <<<"$err"
  check "touches no file" diff -r "$snapshot/m" m
}

test_a_plugin_published_from_another_repo_is_never_overwritten() {
  make_marketplace m && make_plugin p collab 1.0.0
  bash "$SCRIPT" p m psd401/someone-else > /dev/null || { echo "  FAIL: first publish failed"; return 1; }
  set_version p 2.0.0
  local err
  if err=$(bash "$SCRIPT" p m "$REPO" 2>&1 >/dev/null); then echo "  FAIL: script succeeded"; return 1; fi
  check "names the repo it comes from" grep -q "psd401/someone-else" <<<"$err"
}

test_an_entry_with_no_folder_here_is_never_replaced() {
  make_marketplace m && make_plugin p remote 1.0.0
  jq '.plugins += [{"name": "remote", "source": {"source": "git-subdir", "url": "https://example.com/x.git", "path": "p"}}]' \
    m/.claude-plugin/marketplace.json > tmp.json && mv tmp.json m/.claude-plugin/marketplace.json
  if bash "$SCRIPT" p m "$REPO" > /dev/null 2>&1; then echo "  FAIL: script succeeded"; return 1; fi
  check "copies nothing" test ! -e m/plugins/remote
}

for t in $(declare -F | awk '{print $3}' | grep '^test_'); do
  run_test "$t"
done

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all passed"
