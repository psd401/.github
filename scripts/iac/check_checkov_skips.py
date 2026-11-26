#!/usr/bin/env python3
# ABOUTME: Fails a pull request that adds or changes an inline Checkov skip without a live
# ABOUTME: exceptions.yml entry: cited by id, active, naming the check, expiring within a year.
"""Usage: check_checkov_skips.py --head <dir> --base <dir> --baseline <baseline.yaml>
                                 [--exceptions exceptions.yml] [--today YYYY-MM-DD]

standards/08-iac.md 'Checkov baseline' and 'Exceptions file' (Kris, 2026-11-26). Compares the
inline `#checkov:skip=<ID>:<reason>` comments in the .tf and .hcl files of two checkouts of the
caller repo: the pull request's head and its base. Only skips the pull request adds or changes are
checked; skips already on the base branch are reported elsewhere (the janitor) for backfill.

A new skip passes when:
- it has a reason that cites `exceptions.yml#<entry-id>`;
- that entry exists, has status active, and its rule names the check id;
- the entry's expires is a date between today and 366 days from today ("none" is refused);
- the check isn't in the org baseline (policy/checkov/baseline.yaml), which already skips it.

Prints file:line and check id for each failure, never the comment's free text.
"""
import argparse
import collections
import datetime as dt
import re
import sys
from pathlib import Path

import yaml

SKIP = re.compile(r"checkov:skip=([A-Za-z0-9_]+)(?::(.*))?")
CITE = re.compile(r"exceptions\.yml#([A-Za-z0-9._-]+)")
RULE_IDS = re.compile(r"\b(CKV2?_[A-Z0-9]+_)(\d+(?:/\d+)*)")
SUFFIXES = {".tf", ".hcl"}
SKIP_DIRS = {".git", ".terraform", "node_modules", "_policy", "_base"}
MAX_DAYS = 366


def skips(root):
    """[(relpath, line_no, check_id, reason)] for every inline skip under root."""
    root = Path(root)
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in SUFFIXES or not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            m = SKIP.search(line)
            if m:
                out.append((str(rel), n, m.group(1), (m.group(2) or "").strip()))
    return out


def new_skips(head, base):
    """Head skips not on the base branch, matched by file, check id and reason."""
    have = collections.Counter((f, c, r) for f, _, c, r in skips(base)) if Path(base).is_dir() else collections.Counter()
    out = []
    for f, n, c, r in skips(head):
        if have[(f, c, r)]:
            have[(f, c, r)] -= 1
        else:
            out.append((f, n, c, r))
    return out


def rule_ids(rule):
    ids = set()
    for prefix, nums in RULE_IDS.findall(rule or ""):
        ids.update(prefix + n for n in nums.split("/"))
    return ids


def load_entries(path):
    p = Path(path)
    if not p.is_file():
        return {}
    doc = yaml.safe_load(p.read_text()) or {}
    entries = doc.get("exceptions") or []
    return {e.get("id"): e for e in entries if isinstance(e, dict)}


def baseline_ids(path):
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return {c["id"] for c in doc.get("checks", [])}


def problems(skip, entries, baseline, today):
    f, n, check, reason = skip
    where = f"{f}:{n} {check}"
    if check in baseline:
        return [f"{where}: already skipped by the org baseline; delete this skip"]
    if not reason:
        return [f"{where}: no reason after the check id"]
    cited = CITE.findall(reason)
    if not cited:
        return [f"{where}: reason doesn't cite exceptions.yml#<entry-id>"]
    entry = entries.get(cited[0])
    if entry is None:
        return [f"{where}: cites exceptions.yml#{cited[0]}, which isn't in exceptions.yml"]
    errs = []
    if entry.get("status") != "active":
        errs.append(f"{where}: exceptions.yml#{cited[0]} has status {entry.get('status')}, not active")
    if check not in rule_ids(str(entry.get("rule", ""))):
        errs.append(f"{where}: exceptions.yml#{cited[0]}'s rule doesn't name {check}")
    expires = str(entry.get("expires", ""))
    try:
        date = dt.date.fromisoformat(expires)
    except ValueError:
        errs.append(f"{where}: exceptions.yml#{cited[0]} must expire on a date within a year, not {expires!r}")
    else:
        if date < today:
            errs.append(f"{where}: exceptions.yml#{cited[0]} expired on {expires}")
        elif (date - today).days > MAX_DAYS:
            errs.append(f"{where}: exceptions.yml#{cited[0]} expires {expires}, more than a year out")
    return errs


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--exceptions", default="exceptions.yml")
    ap.add_argument("--today")
    a = ap.parse_args(argv)
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    try:
        entries = load_entries(Path(a.head) / a.exceptions)
        baseline = baseline_ids(a.baseline)
    except (yaml.YAMLError, OSError, KeyError, TypeError):
        print("::error::cannot read exceptions.yml or the Checkov baseline", file=sys.stderr)
        return 1
    added = new_skips(a.head, a.base)
    errs = [e for s in added for e in problems(s, entries, baseline, today)]
    for e in errs:
        print(f"::error::{e}", file=sys.stderr)
    print(f"{len(added)} new or changed Checkov skip(s), {len(errs)} problem(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
