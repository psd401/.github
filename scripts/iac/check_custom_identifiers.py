#!/usr/bin/env python3
# ABOUTME: Checks each cloud.aws.student_pii custom data identifier in the env file against
# ABOUTME: the CloudWatch Logs limits and its own test strings, using Python re.
"""Usage: check_custom_identifiers.py --env-file <decoded.env.yml>

For each cloud.aws.student_pii.custom_identifiers entry:
- name: at most 128 characters from a-zA-Z0-9_-
- regex: at most 200 characters, every character in the CloudWatch set
  (alphanumerics, _ # = @ / ; , - space, and ^ $ ? [ ] { } | \\ * + .)
- regex compiles under Python re, every test_matches string matches, and no
  test_non_matches string matches (re.search, since CloudWatch finds an
  identifier anywhere in a log event)
Limits: CloudWatch Logs User Guide, Custom data identifiers, read 2026-10-23.

Python re is an approximation of the CloudWatch engine, and the table says so.
Prints identifier names and the district's test strings only, never a regex
or any other env-file value. Exit 1 on any failure, 0 when every check passes
or the env file has no student_pii block.
"""
import argparse
import re
import string
import sys

import yaml

NAME_LIMIT = 128
REGEX_LIMIT = 200
NAME_CHARS = set(string.ascii_letters + string.digits + "_-")
REGEX_CHARS = set(string.ascii_letters + string.digits + "_#=@/;,- " + "^$?[]{}|\\*+.")


def cell(text):
    return str(text).replace("|", "\\|")


def name_problem(name):
    if not isinstance(name, str) or not name:
        return "missing or not a string"
    if len(name) > NAME_LIMIT:
        return f"{len(name)} characters, limit {NAME_LIMIT}"
    if set(name) - NAME_CHARS:
        return "characters outside a-zA-Z0-9_-"
    return ""


def strings_under(entry, key):
    values = entry.get(key)
    if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
        return None
    return values


def check_identifier(index, entry):
    """Return (label, rows). Each row is (check, test string, ok, detail)."""
    if not isinstance(entry, dict):
        return f"custom_identifiers[{index}]", [("entry", "", False, "not a mapping")]
    name = entry.get("name")
    problem = name_problem(name)
    label = name if isinstance(name, str) and name else f"custom_identifiers[{index}]"
    rows = [("name", "", not problem, problem)]

    regex = entry.get("regex")
    compiled = None
    if not isinstance(regex, str) or not regex:
        rows.append(("regex", "", False, "missing or not a string"))
    else:
        rows.append(("regex length", "", len(regex) <= REGEX_LIMIT,
                     f"{len(regex)} characters, limit {REGEX_LIMIT}"))
        bad = [str(i) for i, c in enumerate(regex) if c not in REGEX_CHARS]
        rows.append(("regex characters", "", not bad,
                     f"positions {', '.join(bad)} outside the CloudWatch character set" if bad else ""))
        try:
            compiled = re.compile(regex)
            rows.append(("regex compiles", "", True, ""))
        except re.error as e:
            rows.append(("regex compiles", "", False,
                         f"does not compile under Python re (error at position {e.pos})"))

    for key, check, want in (("test_matches", "must match", True),
                             ("test_non_matches", "must not match", False)):
        values = strings_under(entry, key)
        if values is None:
            rows.append((check, "", False, f"{key} missing, empty, or not all strings"))
            continue
        for value in values:
            if compiled is None:
                rows.append((check, repr(value), False, "regex not usable"))
            else:
                ok = (compiled.search(value) is not None) == want
                rows.append((check, repr(value), ok, ""))
    return label, rows


def load(env_path):
    """Return (data, error). The error names the file and position, never content."""
    try:
        with open(env_path, encoding="utf-8") as f:
            return yaml.safe_load(f), ""
    except OSError:
        return None, f"{env_path}: cannot read the env file"
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        return None, f"{env_path}: not valid YAML{where}"


def student_pii_block(data):
    """Return (present, block)."""
    aws = ((data or {}).get("cloud") or {}).get("aws") if isinstance(data, dict) else None
    if not isinstance(aws, dict) or "student_pii" not in aws:
        return False, None
    return True, aws["student_pii"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", required=True)
    args = ap.parse_args()

    data, error = load(args.env_file)
    if error:
        print(error, file=sys.stderr)
        return 1
    present, block = student_pii_block(data)
    if not present:
        print(f"{args.env_file}: no student_pii block, nothing to check.")
        return 0
    identifiers = block.get("custom_identifiers") if isinstance(block, dict) else None
    if not isinstance(identifiers, list) or not identifiers:
        print(f"{args.env_file}: cloud.aws.student_pii.custom_identifiers is missing or empty.",
              file=sys.stderr)
        return 1

    print("Custom data identifiers, checked with Python re: an approximation of the CloudWatch "
          "engine. A pass here does not prove CloudWatch matches the same strings.")
    print()
    print("| identifier | check | test string | result | detail |")
    print("|---|---|---|---|---|")
    failures = 0
    for index, entry in enumerate(identifiers):
        label, rows = check_identifier(index, entry)
        for check, shown, ok, detail in rows:
            failures += not ok
            print(f"| {cell(label)} | {check} | {cell(shown)} | {'pass' if ok else 'fail'} | {detail} |")
    print()
    if failures:
        print(f"{args.env_file}: {failures} custom identifier check(s) failed.", file=sys.stderr)
        return 1
    print(f"{args.env_file}: {len(identifiers)} custom identifier(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
