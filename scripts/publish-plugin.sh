#!/usr/bin/env bash
# ABOUTME: Copies a Claude Code plugin into a checked-out marketplace repo and lists it there.
# ABOUTME: Used by reusable-publish-plugin.yml; prints changed/name/version for the workflow.
#
# Usage: publish-plugin.sh <plugin dir> <marketplace dir> <source repo> [category]
#
# The plugin lands in <marketplace>/plugins/<name>/ with a .publish-source file
# naming the repo it came from, and its marketplace.json entry is added (new
# plugins) or given the new version (existing ones). Nothing else in the
# marketplace changes: other plugins, metadata.version and the changelog stay
# with the marketplace's maintainers.
#
# Refuses, changing nothing, when:
# - plugin.json has no plain one-line version, or a name that isn't a lowercase
#   slug (both come from the calling repo; the name becomes a path);
# - plugins/<name>/ exists but wasn't published from this source repo, or the
#   marketplace lists <name> with no folder here (a plugin someone else keeps);
# - the plugin changed but its version didn't. Installs update only when the
#   version changes, so the new files would never reach anyone.
set -euo pipefail

if [ $# -lt 3 ]; then
  echo "usage: publish-plugin.sh <plugin dir> <marketplace dir> <source repo> [category]" >&2
  exit 2
fi
src=${1%/}
market=${2%/}
source_repo=$3
category=${4:-}

refuse() {
  echo "::error::$1" >&2
  exit 1
}

manifest="$src/.claude-plugin/plugin.json"
catalog="$market/.claude-plugin/marketplace.json"
[ -f "$manifest" ] || refuse "No plugin at $src: $manifest is missing."
[ -f "$catalog" ] || refuse "No marketplace at $market: $catalog is missing."

name=$(jq -r '.name // ""' "$manifest")
version=$(jq -r '.version // ""' "$manifest")
[[ "$name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] \
  || refuse "plugin.json's name '$name' must be lowercase letters, digits and single hyphens."
[ -n "$version" ] \
  || refuse "plugin.json needs a version: installs update only when it changes. Add \"version\": \"1.0.0\"."
# One line of version characters: it goes into the workflow's step outputs.
[[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] \
  || refuse "plugin.json's version '$version' must be a plain version like 1.2.0."

dest="$market/plugins/$name"
marker="$dest/.publish-source"
listed=$(jq --arg name "$name" '[.plugins[] | select(.name == $name)] | length' "$catalog")

if [ -d "$dest" ]; then
  owner=$(cat "$marker" 2>/dev/null || true)
  [ "$owner" = "$source_repo" ] || refuse \
    "plugins/$name isn't published from $source_repo (it's ${owner:-maintained in the marketplace itself}). Rename the plugin, or ask that repo's maintainers."
  if diff -r -q -x .publish-source -x .git "$src" "$dest" > /dev/null; then
    echo "changed=false"
    echo "name=$name"
    echo "version=$version"
    exit 0
  fi
  published=$(jq -r '.version // ""' "$dest/.claude-plugin/plugin.json")
  [ "$published" != "$version" ] || refuse \
    "The plugin changed but is still version $version, so no install would update. Bump \"version\" in plugin.json."
elif [ "$listed" -gt 0 ]; then
  refuse "The marketplace already lists a plugin named '$name' that isn't kept in plugins/$name. Rename the plugin."
fi

mkdir -p "$dest"
rsync -a --delete --exclude .publish-source --exclude .git "$src/" "$dest/"
printf '%s\n' "$source_repo" > "$marker"

updated=$(mktemp)
if [ "$listed" -gt 0 ]; then
  jq --arg name "$name" --arg version "$version" \
    '(.plugins[] | select(.name == $name) | .version) = $version' "$catalog" > "$updated"
else
  # Fields in the order psd-claude-plugins' entries use.
  jq --arg name "$name" --arg version "$version" --arg category "$category" --slurpfile manifest "$manifest" '
    $manifest[0] as $m
    | .plugins += [
        {name: $name, source: "./plugins/\($name)", description: ($m.description // ""), version: $version}
        + (if $category != "" then {category: $category} else {} end)
        + (if $m.keywords then {keywords: $m.keywords} else {} end)
      ]' "$catalog" > "$updated"
fi
mv "$updated" "$catalog"

echo "changed=true"
echo "name=$name"
echo "version=$version"
