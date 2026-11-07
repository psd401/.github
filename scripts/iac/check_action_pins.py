#!/usr/bin/env python3
# ABOUTME: Fails when a SHA-pinned `uses:` names a path that does not exist at that
# ABOUTME: SHA, or an action that declares a Node runtime GitHub has removed.
"""Usage: check_action_pins.py <workflow.yml>...

actionlint and zizmor read only the calling file, so a pin to a commit
where the action's subdirectory or the reusable workflow file is absent
passes both and fails at run time. This reads each pinned target from
raw.githubusercontent.com at its SHA. Unpinned refs are
reusable-security-scan.yml's job (zizmor) and are skipped here.
"""
import os
import re
import sys
import urllib.error
import urllib.request

USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^\s'"#]+)""", re.MULTILINE)
USING = re.compile(r"""^\s*using:\s*['"]?([\w-]+)""", re.MULTILINE)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# GitHub-hosted runners no longer ship these (changelog 2026-09-23,
# "Node 20 is no longer available in GitHub Actions").
REMOVED_RUNTIMES = {"node12", "node16", "node20"}


def fetch_raw(owner_repo, sha, path):
    """Private repos 404 without a token, so GITHUB_TOKEN (or GH_TOKEN) is
    sent when set. Public targets need none."""
    req = urllib.request.Request(f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def pinned_refs(text):
    seen = []
    for ref in USES.findall(text):
        if ref.startswith(("./", "docker://")) or "@" not in ref:
            continue
        target, sha = ref.rsplit("@", 1)
        if FULL_SHA.match(sha) and ref not in seen:
            seen.append(ref)
    return seen


def problem_for(ref, fetch, cache):
    if ref in cache:
        return cache[ref]
    target, sha = ref.rsplit("@", 1)
    parts = target.split("/")
    owner_repo, sub = "/".join(parts[:2]), "/".join(parts[2:])
    result = None
    if sub.startswith(".github/workflows/"):
        if fetch(owner_repo, sha, sub) is None:
            result = f"{ref}: {sub} does not exist at that SHA"
    else:
        prefix = f"{sub}/" if sub else ""
        text = fetch(owner_repo, sha, f"{prefix}action.yml")
        if text is None:
            text = fetch(owner_repo, sha, f"{prefix}action.yaml")
        if text is None:
            result = f"{ref}: no action.yml at that SHA"
        else:
            m = USING.search(text)
            if m and m.group(1) in REMOVED_RUNTIMES:
                result = (f"{ref} declares runs.using {m.group(1)}, "
                          "which GitHub-hosted runners no longer ship")
    cache[ref] = result
    return result


def check(files, fetch=fetch_raw):
    cache, problems = {}, []
    for f in files:
        for ref in pinned_refs(open(f, encoding="utf-8").read()):
            p = problem_for(ref, fetch, cache)
            if p:
                problems.append(f"{f}: {p}")
    return problems


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    problems = check(argv)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
