# ABOUTME: Checks policy/data/telemetry-layers.yml, the vendor Lambda layer list student_pii_destinations.rego
# ABOUTME: matches: row fields, anchored patterns that match their examples, and a warning past 180 days.
"""A row names a vendor whose Lambda layer sends function telemetry to a
party outside the root (destination kind lambda-telemetry). Vendor accounts
and layer names change, so every row carries verified_on. A row older than
MAX_AGE_DAYS, or marked UNVERIFIED, raises StaleTelemetryRow in this repo's
pytest run (FINAL-PLAN M5). The warning does not fail the run. The conftest
test runs the shipped list through the real policy, so OPA's regex engine
compiles every pattern. Needs conftest on PATH (or CONFTEST);
REQUIRE_CONFTEST=1 turns the skip into a failure, as psd-ci sets it."""
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import warnings
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LAYERS = ROOT / "policy" / "data" / "telemetry-layers.yml"
FIELDS = {"vendor", "match", "example", "operator", "verified_on", "source"}
MAX_AGE_DAYS = 180
UNVERIFIED = "UNVERIFIED"
OWN_LAYER = "arn:aws:lambda:us-west-2:111111111111:layer:shared-utils:3"
FUNCTION = "aws_lambda_function.probe"
TODAY = dt.date(2026, 10, 23)


class StaleTelemetryRow(UserWarning):
    """A telemetry-layers.yml row past MAX_AGE_DAYS or marked UNVERIFIED."""


def rows():
    return yaml.safe_load(LAYERS.read_text(encoding="utf-8"))["telemetry_layers"]


def stale_rows(entries, today):
    """Rows whose verified_on is UNVERIFIED or more than MAX_AGE_DAYS before today."""
    return [row for row in entries
            if row["verified_on"] == UNVERIFIED
            or (today - dt.date.fromisoformat(row["verified_on"])).days > MAX_AGE_DAYS]


def warn_stale(entries, today):
    for row in stale_rows(entries, today):
        warnings.warn(StaleTelemetryRow(
            f"telemetry-layers.yml {row['vendor']}: verified_on {row['verified_on']} is UNVERIFIED or more than "
            f"{MAX_AGE_DAYS} days old. Re-check {row.get('source')} and update the row"))


def conftest_bin():
    found = os.environ.get("CONFTEST") or shutil.which("conftest")
    if not found:
        if os.environ.get("REQUIRE_CONFTEST") == "1":
            pytest.fail("REQUIRE_CONFTEST=1 but conftest is not on PATH")
        pytest.skip("conftest is not on PATH")
    return found


def test_every_row_has_the_fields_and_an_https_source():
    entries = rows()
    assert entries
    for row in entries:
        assert set(row) == FIELDS, row
        assert all(isinstance(row[f], str) and row[f].strip() for f in FIELDS), row
        assert row["source"].startswith("https://"), row
    vendors = [row["vendor"] for row in entries]
    assert len(vendors) == len(set(vendors))


def test_verified_on_is_a_quoted_past_date_or_unverified():
    for row in rows():
        assert isinstance(row["verified_on"], str), f"quote verified_on, a bare YAML date is not a string: {row}"
        if row["verified_on"] != UNVERIFIED:
            assert dt.date.fromisoformat(row["verified_on"]) <= dt.date.today(), row


def test_each_match_is_anchored_matches_its_example_and_not_an_own_layer():
    for row in rows():
        assert row["match"].startswith("^arn:aws"), row
        pattern = re.compile(row["match"])
        assert pattern.match(row["example"]), row
        assert not pattern.match(OWN_LAYER), row


def test_row_verified_180_days_ago_is_fresh_and_181_days_ago_is_stale():
    fresh = {"vendor": "Fresh", "verified_on": str(TODAY - dt.timedelta(days=180))}
    old = {"vendor": "Old", "verified_on": str(TODAY - dt.timedelta(days=181))}
    assert stale_rows([fresh, old], TODAY) == [old]


def test_unverified_row_warns():
    row = {"vendor": "Unchecked", "verified_on": UNVERIFIED, "source": "https://example.com/layers"}
    with pytest.warns(StaleTelemetryRow, match="Unchecked: verified_on UNVERIFIED"):
        warn_stale([row], TODAY)


def test_shipped_list_warns_on_stale_rows():
    """A stale row shows in the warnings summary until someone re-checks its source."""
    warn_stale(rows(), dt.date.today())


def test_conftest_flags_every_example_layer_with_the_shipped_list(tmp_path):
    entries = rows()
    plan = {"resource_changes": [
        {"address": "aws_s3_bucket.data", "type": "aws_s3_bucket",
         "change": {"actions": ["create"], "after": {"tags_all": {"psd:data-classification": "student-pii"}}}},
        {"address": FUNCTION, "type": "aws_lambda_function",
         "change": {"actions": ["create"],
                    "after": {"function_name": "probe", "layers": [row["example"] for row in entries] + [OWN_LAYER]}}},
    ]}
    (tmp_path / "tfplan.json").write_text(json.dumps(plan))
    out = subprocess.run([conftest_bin(), "test", "tfplan.json", "--policy", str(ROOT / "policy/conftest/aws"),
                          "--data", str(LAYERS), "--all-namespaces", "--output", "json"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert out.stdout.lstrip().startswith("["), out.stderr
    msgs = [f["msg"] for r in json.loads(out.stdout) for f in (r.get("failures") or [])]
    for row in entries:
        expected = f"{FUNCTION}: student-pii root, Lambda layer {row['example']} ({row['vendor']}) " \
                   "(destination kind lambda-telemetry)"
        assert any(m.startswith(expected) for m in msgs), expected
    assert not any(OWN_LAYER in m for m in msgs)
