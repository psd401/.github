# ABOUTME: Tests for check_exceptions.py: schema-validate exceptions.yml and require an
# ABOUTME: active, unexpired entry for each standard the calling repo must carry.
"""Tests for check_exceptions.py, the exceptions cross-check both reusable
workflows run: schema-validate exceptions.yml, and require an active,
unexpired entry for each standard the calling repo must carry."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).parent
SCRIPT = HERE / "check_exceptions.py"
SCHEMA = HERE.parent.parent / "schemas" / "iac" / "exceptions.schema.json"
FIX = HERE / "fixtures" / "exceptions"
RULE44 = "15-onprem-platform.md#11-app-runtime-bones"


def run(*args, today="2026-10-22"):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--schema", str(SCHEMA), "--today", today, *args],
        capture_output=True, text=True)


def test_active_matching_entry_passes():
    r = run("--require", RULE44, str(FIX / "rule44_active.yml"))
    assert r.returncode == 0, r.stderr


def test_retired_entry_plus_unrelated_active_entry_fails():
    r = run("--require", RULE44, str(FIX / "rule44_retired_plus_unrelated_active.yml"))
    assert r.returncode == 1
    assert RULE44 in r.stderr
    assert "superseded" in r.stderr


def test_expired_entry_fails():
    r = run("--require", RULE44, str(FIX / "rule44_expired.yml"))
    assert r.returncode == 1
    assert "expired" in r.stderr


def test_expired_entry_passes_before_its_date():
    r = run("--require", RULE44, str(FIX / "rule44_expired.yml"), today="2025-12-31")
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("today", ["", "2026-9-1", "2026-02-30"])
def test_today_that_is_not_a_date_is_refused(today):
    """Expiry compares YYYY-MM-DD strings, so an empty --today would keep every entry unexpired."""
    r = run("--require", RULE44, str(FIX / "rule44_expired.yml"), today=today)
    assert r.returncode == 2
    assert "--today" in r.stderr


def test_today_defaults_to_a_date():
    r = subprocess.run([sys.executable, str(SCRIPT), "--schema", str(SCHEMA),
                        "--require", RULE44, str(FIX / "rule44_active.yml")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_missing_file_with_requirement_fails(tmp_path):
    r = run("--require", RULE44, str(tmp_path / "exceptions.yml"))
    assert r.returncode == 1
    assert "no exceptions.yml" in r.stderr


def test_missing_file_without_requirement_passes(tmp_path):
    r = run(str(tmp_path / "exceptions.yml"))
    assert r.returncode == 0, r.stderr


def test_schema_violation_fails_even_without_requirement():
    r = run(str(FIX / "invalid_schema.yml"))
    assert r.returncode == 1
    assert "schema" in r.stderr


def test_empty_list_passes_without_requirement():
    r = run(str(FIX / "empty.yml"))
    assert r.returncode == 0, r.stderr


def test_empty_scope_fails():
    """An empty scope is a prefix of every address, so it would waive every finding."""
    r = run(str(FIX / "empty_scope.yml"))
    assert r.returncode == 1
    assert "schema violation at exceptions/0/scope" in r.stderr


def test_whitespace_scope_fails():
    r = run(str(FIX / "whitespace_scope.yml"))
    assert r.returncode == 1
    assert "schema violation at exceptions/0/scope" in r.stderr


def test_expires_that_is_neither_a_date_nor_none_fails():
    r = run(str(FIX / "bad_expires.yml"))
    assert r.returncode == 1
    assert "schema violation at exceptions/0/expires" in r.stderr


def test_duplicate_ids_fail():
    r = run(str(FIX / "duplicate_ids.yml"))
    assert r.returncode == 1
    assert "duplicate id 'same-id'" in r.stderr
    assert "Second entry" not in r.stdout + r.stderr


def test_approved_by_description_claims_no_approving_review():
    """03-code-review.md, CIO decision 2026-10-22: no approval requirement anywhere."""
    props = json.loads(SCHEMA.read_text())["$defs"]["exception"]["properties"]
    assert "approving review" not in props["approved_by"]["description"]



def fixture_entry(name):
    return yaml.safe_load((FIX / name).read_text())["exceptions"][0]


def entry_errors(entry):
    """(path, failing keyword) for every schema error in a one-entry file."""
    schema = json.loads(SCHEMA.read_text())
    return {("/".join(str(p) for p in e.absolute_path), e.validator)
            for e in Draft202012Validator(schema).iter_errors({"exceptions": [entry]})}


@pytest.mark.parametrize("name", ["in_logs.yml", "log_destination.yml", "downgrade.yml"])
def test_student_pii_fixtures_validate_and_pass(name):
    """Student-pii entries need no signed record: the check passes them like any other."""
    assert entry_errors(fixture_entry(name)) == set()
    r = run(str(FIX / name))
    assert r.returncode == 0, r.stderr


def test_log_destination_entry_needs_a_destination_block():
    entry = fixture_entry("log_destination.yml")
    del entry["destination"]
    assert entry_errors(entry) == {("exceptions/0", "required")}


@pytest.mark.parametrize("field, value, error", [
    ("kind", "kinesis", ("exceptions/0/destination/kind", "enum")),
    ("retention_days", 0, ("exceptions/0/destination/retention_days", "minimum")),
    ("retention_days", 7.5, ("exceptions/0/destination/retention_days", "type")),
    ("kms", "yes", ("exceptions/0/destination/kms", "type")),
    ("operator", None, ("exceptions/0/destination", "required")),
    ("target", None, ("exceptions/0/destination", "required")),
    ("region", "us-west-2", ("exceptions/0/destination", "additionalProperties")),
])
def test_destination_block_fields(field, value, error):
    entry = fixture_entry("log_destination.yml")
    if value is None:
        del entry["destination"][field]
    else:
        entry["destination"][field] = value
    assert entry_errors(entry) == {error}


def test_destination_block_on_another_standard_is_not_required():
    entry = fixture_entry("in_logs.yml")
    assert "destination" not in entry
    assert entry_errors(entry) == set()
