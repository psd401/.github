#!/usr/bin/env python3
# ABOUTME: Schema-validates a repo's exceptions.yml and requires an active, unexpired entry
# ABOUTME: for each --require standard. Used by both IaC reusables.
"""Exceptions cross-check for the reusable IaC workflows.

Usage: check_exceptions.py --schema <exceptions.schema.json>
                           [--require <file.md#anchor>]... [--today YYYY-MM-DD]
                           [exceptions.yml]

1. If exceptions.yml exists, it must validate against the schema, and no
   two entries may share an id (code comments cite an entry by its id).
2. For every --require, one entry must match that standard string exactly
   (standards/08-iac.md 'Exceptions file': full file-plus-anchor, never a
   substring), be status: active, and be unexpired. Each requirement is
   checked against single entries, so a retired entry for the required
   standard plus an unrelated active entry does not pass.

--today must be a real YYYY-MM-DD date and defaults to today in UTC; dates
compare as YYYY-MM-DD strings.

Prints paths and standard ids only, never an entry's free-text fields.
"""
import argparse
import datetime as dt
import json
import re
import sys

import yaml
from jsonschema import Draft202012Validator

DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def iso_date(value):
    """A YYYY-MM-DD string as a date. Expiry compares strings, so a value that
    is not a real date (empty, unpadded, 02-30) is refused."""
    try:
        if DATE.fullmatch(value):
            return dt.date.fromisoformat(value)
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("must be a YYYY-MM-DD date")


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def schema_errors(data, schema_path):
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    errors = sorted(Draft202012Validator(schema).iter_errors(data),
                    key=lambda e: list(e.absolute_path))
    return ["/".join(str(p) for p in e.absolute_path) or "(root)" for e in errors]


def duplicate_ids(entries):
    """Return (index, id) for every entry whose id an earlier entry already used."""
    seen, dupes = set(), []
    for i, entry in enumerate(entries):
        if entry["id"] in seen:
            dupes.append((i, entry["id"]))
        seen.add(entry["id"])
    return dupes


def unexpired(entry, today):
    expires = str(entry.get("expires", ""))
    return expires == "none" or expires >= today


def satisfied(entries, standard, today):
    """Return (ok, reason). Reason names the closest non-matching entry."""
    reasons = []
    for entry in entries:
        if entry.get("standard") != standard:
            continue
        status = entry.get("status")
        if status != "active":
            reasons.append(f"entry {entry.get('id')!r} has status {status}")
        elif not unexpired(entry, today):
            reasons.append(f"entry {entry.get('id')!r} expired on {entry.get('expires')}")
        else:
            return True, ""
    return False, "; ".join(reasons) or "no entry cites it"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--require", action="append", default=[])
    ap.add_argument("--today", type=iso_date, default=dt.datetime.now(dt.timezone.utc).date(),
                    help="YYYY-MM-DD; defaults to today in UTC")
    ap.add_argument("path", nargs="?", default="exceptions.yml")
    args = ap.parse_args()
    args.today = args.today.isoformat()

    try:
        data = load(args.path)
    except FileNotFoundError:
        if args.require:
            print(f"{args.path}: this repo must carry an active exception for "
                  f"{', '.join(args.require)}, but it has no exceptions.yml.", file=sys.stderr)
            return 1
        print(f"{args.path}: not present, and nothing requires one.")
        return 0

    bad = schema_errors(data, args.schema)
    if bad:
        for loc in bad:
            print(f"{args.path}: schema violation at {loc}", file=sys.stderr)
        return 1

    entries = data.get("exceptions") or []
    dupes = duplicate_ids(entries)
    if dupes:
        for i, entry_id in dupes:
            print(f"{args.path}: duplicate id {entry_id!r} at exceptions/{i}", file=sys.stderr)
        return 1

    failed = False
    for standard in args.require:
        ok, reason = satisfied(entries, standard, args.today)
        if not ok:
            failed = True
            print(f"{args.path}: no active, unexpired entry for {standard} ({reason}).",
                  file=sys.stderr)
    if failed:
        return 1
    print(f"{args.path}: valid; {len(args.require)} required standard(s) satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
