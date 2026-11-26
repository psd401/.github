#!/usr/bin/env python3
# ABOUTME: Prints the comma-separated Checkov skip list for reusable-iac-checks.yml: the org
# ABOUTME: baseline (policy/checkov/baseline.yaml) plus the calling repo's .checkov.yaml skip-check.
"""Usage: checkov_skip_list.py --baseline <baseline.yaml> [--repo-config <.checkov.yaml>]

checkov-action's skip_check input becomes --skip-check on the command line, which replaces a
skip-check list in the repo's .checkov.yaml rather than adding to it. So the caller's list is
read here and merged with the baseline: a repo keeps every skip it had, and gets the baseline.

Exits 1, naming the file, when either file isn't the expected shape or an entry isn't a Checkov
check id (CKV_..., CKV2_..., or a custom id from the repo's own config). Prints ids only.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

CHECK_ID = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")
BASELINE_KEYS = {"id", "title", "standard", "reason"}


class Bad(Exception):
    pass


def baseline_ids(path):
    doc = yaml.safe_load(Path(path).read_text())
    checks = doc.get("checks") if isinstance(doc, dict) else None
    if not isinstance(checks, list) or not checks:
        raise Bad(f"{path}: needs a non-empty 'checks' list")
    ids = []
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict) or set(entry) != BASELINE_KEYS:
            raise Bad(f"{path}: checks[{i}] needs exactly {sorted(BASELINE_KEYS)}")
        if not all(isinstance(entry[k], str) and entry[k].strip() for k in BASELINE_KEYS):
            raise Bad(f"{path}: checks[{i}] has an empty field")
        if not CHECK_ID.match(entry["id"]):
            raise Bad(f"{path}: checks[{i}].id is not a Checkov check id")
        ids.append(entry["id"])
    if len(set(ids)) != len(ids):
        raise Bad(f"{path}: a check id appears twice")
    return ids


def repo_ids(path):
    p = Path(path)
    if not p.is_file():
        return []
    doc = yaml.safe_load(p.read_text()) or {}
    if not isinstance(doc, dict):
        raise Bad(f"{path}: not a mapping")
    raw = doc.get("skip-check", doc.get("skip_check", []))
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [s.strip() for s in raw.split(",") if s.strip()]
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise Bad(f"{path}: skip-check must be a list of check ids")
    for s in raw:
        if not CHECK_ID.match(s):
            raise Bad(f"{path}: skip-check has an entry that is not a check id")
    return raw


def merged(baseline, repo):
    out = []
    for s in baseline + repo:
        if s not in out:
            out.append(s)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--repo-config", default=".checkov.yaml")
    a = ap.parse_args(argv)
    try:
        ids = merged(baseline_ids(a.baseline), repo_ids(a.repo_config))
    except (Bad, yaml.YAMLError, OSError) as e:
        msg = str(e) if isinstance(e, Bad) else f"cannot read {a.baseline} or {a.repo_config}"
        print(f"::error::{msg}", file=sys.stderr)
        return 1
    print(",".join(ids))
    return 0


if __name__ == "__main__":
    sys.exit(main())
