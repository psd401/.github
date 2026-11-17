# ABOUTME: Tests for check_classification_downgrade.py: a resource whose psd:data-classification
# ABOUTME: leaves student-pii in the plan fails unless an exact, active downgrade entry waives it.
"""standards/08-iac.md 'Student PII downgrade'. Plans are fixtures/downgrade/,
shaped like `terraform show -json` from Terraform 1.16.5 with hashicorp/aws
6.70.0. The waiver is fixtures/exceptions/downgrade.yml."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).parent
SCRIPT = HERE / "check_classification_downgrade.py"
REDACT = HERE / "redact_plan.py"
FIX = HERE / "fixtures" / "downgrade"
DOWNGRADE = HERE / "fixtures" / "exceptions" / "downgrade.yml"
IN_LOGS = HERE / "fixtures" / "exceptions" / "in_logs.yml"
TODAY = "2026-10-23"


def run(plan, exceptions, today=TODAY):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--plan-json", str(plan), "--exceptions", str(exceptions),
         "--today", today],
        capture_output=True, text=True)


def no_file(tmp_path):
    return tmp_path / "exceptions.yml"


def test_tag_removed_without_downgrade_entry_fails(tmp_path):
    """default_tags moves the root off student-pii, so tags_all changes on the resource."""
    r = run(FIX / "plan_tag_dropped.json", no_file(tmp_path))
    assert r.returncode == 1
    lines = r.stderr.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("aws_s3_bucket.archive: ")
    assert "'internal'" in lines[0]
    assert "08-iac.md#student-pii-downgrade" in lines[0]


def test_active_exact_entry_passes():
    r = run(FIX / "plan_tag_dropped.json", DOWNGRADE)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("OK")
    assert len(r.stdout.splitlines()) == 1


def test_expired_entry_fails():
    r = run(FIX / "plan_tag_dropped.json", DOWNGRADE, today="2027-07-01")
    assert r.returncode == 1
    assert "aws_s3_bucket.archive" in r.stderr
    assert "expired on 2027-06-30" in r.stderr


@pytest.mark.parametrize("today", ["", "2027-7-1", "2027-02-30"])
def test_today_that_is_not_a_date_is_refused(today):
    """Expiry compares YYYY-MM-DD strings, so an empty --today would keep the entry unexpired."""
    r = run(FIX / "plan_tag_dropped.json", DOWNGRADE, today=today)
    assert r.returncode == 2
    assert "--today" in r.stderr


@pytest.mark.parametrize("scope", ["*", "aws_s3_bucket.*", "aws_s3_bucket.", "aws_s3_bucket"])
def test_wildcard_or_prefix_scope_fails(tmp_path, scope):
    data = yaml.safe_load(DOWNGRADE.read_text())
    data["exceptions"][0]["scope"] = scope
    exceptions = tmp_path / "exceptions.yml"
    exceptions.write_text(yaml.safe_dump(data))
    r = run(FIX / "plan_tag_dropped.json", exceptions)
    assert r.returncode == 1
    assert r.stderr.startswith("aws_s3_bucket.archive: ")


def test_replace_that_drops_the_tag_fails():
    """The new log group has no classification tag. in_logs.yml scopes this exact
    address under 08-iac.md#student-pii-in-logs, which waives no downgrade."""
    r = run(FIX / "plan_replace.json", IN_LOGS)
    assert r.returncode == 1
    assert r.stderr.startswith("module.sync.aws_cloudwatch_log_group.errors: ")
    assert "replace" in r.stderr
    assert "absent" in r.stderr


def test_tag_unknown_until_apply_fails(tmp_path):
    """A tag value known only after apply leaves tags_all unknown in the plan: not
    provably student-pii, so it counts as a downgrade."""
    r = run(FIX / "plan_unknown_tag.json", no_file(tmp_path))
    assert r.returncode == 1
    assert r.stderr.startswith("aws_cloudwatch_log_group.child: ")
    assert "unknown until apply" in r.stderr


@pytest.mark.parametrize("name", ["plan_unrelated_tag_change.json", "plan_never_student_pii.json",
                                  "plan_delete.json"])
def test_change_that_is_not_a_downgrade_passes(tmp_path, name):
    """In turn: another tag changes while student-pii stays, a resource that was never
    student-pii changes class, and a student-pii resource is deleted with no replacement."""
    r = run(FIX / name, no_file(tmp_path))
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("OK")


def test_tags_survive_redaction(tmp_path):
    """The conftest job reads redact_plan.py output, which cuts prior_state to IAM policy
    and attachment attributes, so no tags survive there. The check reads
    resource_changes[].change.before, so the redacted plan fails the same way."""
    redacted = tmp_path / "tfplan.json"
    subprocess.run([sys.executable, str(REDACT), str(FIX / "plan_tag_dropped.json"), str(redacted)],
                   check=True)
    assert json.loads(redacted.read_text())["prior_state"] == {"values": {"root_module": {}}}
    r = run(redacted, no_file(tmp_path))
    assert r.returncode == 1
    assert r.stderr.startswith("aws_s3_bucket.archive: ")
