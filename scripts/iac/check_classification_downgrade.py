#!/usr/bin/env python3
# ABOUTME: Fails a Terraform plan in which a resource's psd:data-classification leaves student-pii,
# ABOUTME: unless an active exceptions.yml entry for 08-iac.md#student-pii-downgrade names its address.
"""Usage: check_classification_downgrade.py --plan-json <tfplan.json>
                                          [--exceptions exceptions.yml] [--today YYYY-MM-DD]

standards/08-iac.md 'Student PII downgrade'. A resource in resource_changes
is a downgrade when change.before carries psd:data-classification =
student-pii in tags or tags_all and change.after carries it in neither. That
covers:
- a resource-level tag edit
- a provider default_tags edit: the provider recomputes tags_all on every
  resource it tags, so a root-level relabel shows on each of them as an
  update (Terraform 1.16.5, hashicorp/aws 6.70.0)
- a replace whose new object has another value or no tag
- a tag unknown until apply, which the plan cannot show to be student-pii
A delete with no replacement (change.after is null) is not a downgrade.

Reads change.before, never prior_state: the plan is redact_plan.py output,
which drops prior_state and keeps tags, since no provider marks them
sensitive.

An entry waives one downgrade when its standard is
08-iac.md#student-pii-downgrade, its scope equals the resource address, and
it is active and unexpired on --today (check_exceptions.satisfied), a real
YYYY-MM-DD date that defaults to today in UTC. A prefix
or wildcard scope waives nothing.

Prints one line per unwaived downgrade to stderr, naming the address, and
exits 1. Otherwise prints one OK line and exits 0. A missing exceptions file
waives nothing.
"""
import argparse
import datetime as dt
import json
import sys

from check_exceptions import iso_date, load, satisfied

RULE = "08-iac.md#student-pii-downgrade"
KEY = "psd:data-classification"
STUDENT_PII = "student-pii"


def classifications(values):
    """The classification values a before or after object carries in tags and tags_all."""
    if not isinstance(values, dict):
        return set()
    return {m.get(KEY) for m in (values.get("tags"), values.get("tags_all")) if isinstance(m, dict)}


def unknown(change, attr):
    flag = (change.get("after_unknown") or {}).get(attr)
    return flag is True or (isinstance(flag, dict) and flag.get(KEY) is True)


def planned(change):
    """Words for the planned classification of a resource that loses student-pii."""
    for attr in ("tags_all", "tags"):
        tags = change["after"].get(attr)
        if isinstance(tags, dict) and KEY in tags:
            return repr(tags[KEY])
    if unknown(change, "tags_all") or unknown(change, "tags"):
        return "unknown until apply"
    return "absent"


def action(actions):
    return "replace" if set(actions) == {"delete", "create"} else "/".join(actions)


def downgrades(plan):
    """(address, action, planned words) for every resource that loses student-pii."""
    for rc in plan.get("resource_changes") or []:
        change = rc.get("change") or {}
        if rc.get("mode") == "data" or not isinstance(change.get("after"), dict):
            continue
        if (STUDENT_PII in classifications(change.get("before"))
                and STUDENT_PII not in classifications(change["after"])):
            yield rc["address"], action(change.get("actions") or []), planned(change)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan-json", required=True)
    ap.add_argument("--exceptions", default="exceptions.yml")
    ap.add_argument("--today", type=iso_date, default=dt.datetime.now(dt.timezone.utc).date(),
                    help="YYYY-MM-DD; defaults to today in UTC")
    args = ap.parse_args()
    args.today = args.today.isoformat()

    with open(args.plan_json, encoding="utf-8") as f:
        plan = json.load(f)
    try:
        entries = (load(args.exceptions) or {}).get("exceptions") or []
    except FileNotFoundError:
        entries = []

    found = list(downgrades(plan))
    unwaived = 0
    for address, act, new in found:
        exact = [e for e in entries if isinstance(e, dict) and e.get("scope") == address]
        ok, reason = satisfied(exact, RULE, args.today)
        if not ok:
            unwaived += 1
            print(f"{address}: {KEY} goes from student-pii to {new} ({act}), and no active, "
                  f"unexpired exceptions.yml entry for {RULE} has exactly this address as its "
                  f"scope ({reason}).", file=sys.stderr)
    if unwaived:
        return 1
    print(f"OK: no unwaived student-pii downgrade in {args.plan_json} "
          f"({len(found)} waived by an exact {RULE} entry).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
