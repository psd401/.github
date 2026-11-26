# ABOUTME: Tests for check_checkov_skips.py: only skips a PR adds or changes are checked, and each
# ABOUTME: needs a cited, active exceptions.yml entry naming the check and expiring within a year.
"""standards/08-iac.md 'Checkov baseline' (Kris, 2026-11-26): exceptions.yml model, a dated
expiry of at most a year, new skips only."""
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
SCRIPT = HERE / "check_checkov_skips.py"
BASELINE = HERE.parent.parent / "policy" / "checkov" / "baseline.yaml"
TODAY = "2026-11-26"

EXC = """exceptions:
  - id: log-retention
    standard: "12-cloud-cost.md"
    rule: "Checkov CKV_AWS_158: log groups use a customer-managed key"
    reason: r
    scope: "main.tf#aws_cloudwatch_log_group.a"
    approved_by: "IaC owner role"
    status: active
    expires: "2027-06-01"
  - id: kms-policies
    standard: "08-iac.md"
    rule: "Checkov CKV_AWS_109/111/356: IAM *"
    reason: r
    scope: "main.tf#aws_kms_key.a"
    approved_by: "IaC owner role"
    status: active
    expires: "2027-01-01"
  - id: forever
    standard: "08-iac.md"
    rule: "Checkov CKV_AWS_18: access logs"
    reason: r
    scope: "main.tf#aws_s3_bucket.a"
    approved_by: "IaC owner role"
    status: active
    expires: "none"
  - id: too-far
    standard: "08-iac.md"
    rule: "Checkov CKV_AWS_18: access logs"
    reason: r
    scope: "main.tf#aws_s3_bucket.a"
    approved_by: "IaC owner role"
    status: active
    expires: "2028-06-01"
  - id: gone
    standard: "08-iac.md"
    rule: "Checkov CKV_AWS_18: access logs"
    reason: r
    scope: "main.tf#aws_s3_bucket.a"
    approved_by: "IaC owner role"
    status: active
    expires: "2026-01-01"
  - id: pending
    standard: "08-iac.md"
    rule: "Checkov CKV_AWS_18: access logs"
    reason: r
    scope: "main.tf#aws_s3_bucket.a"
    approved_by: "IaC owner role"
    status: pending-review
    expires: "2027-01-01"
"""


def repo(tmp_path, name, tf, exceptions=EXC):
    d = tmp_path / name
    (d / "envs" / "dev").mkdir(parents=True)
    (d / "envs" / "dev" / "main.tf").write_text(tf)
    if exceptions is not None:
        (d / "exceptions.yml").write_text(exceptions)
    return d


def run(head, base):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--head", str(head), "--base", str(base),
         "--baseline", str(BASELINE), "--today", TODAY],
        capture_output=True, text=True)


def skip(check, reason):
    return f'resource "x" "a" {{\n  #checkov:skip={check}:{reason}\n}}\n'


def test_new_skip_citing_a_live_entry_passes(tmp_path):
    head = repo(tmp_path, "head", skip("CKV_AWS_158", "dev log group on the AWS key; see exceptions.yml#log-retention"))
    base = repo(tmp_path, "base", "")
    r = run(head, base)
    assert r.returncode == 0, r.stderr
    assert "1 new or changed" in r.stdout


def test_slash_range_in_rule_names_each_check(tmp_path):
    head = repo(tmp_path, "head", skip("CKV_AWS_111", "key policy; exceptions.yml#kms-policies"))
    r = run(head, repo(tmp_path, "base", ""))
    assert r.returncode == 0, r.stderr


def test_skip_already_on_base_is_not_checked(tmp_path):
    tf = skip("CKV_AWS_18", "old skip with no citation")
    r = run(repo(tmp_path, "head", tf), repo(tmp_path, "base", tf))
    assert r.returncode == 0, r.stderr
    assert "0 new or changed" in r.stdout


def test_moved_skip_is_not_new(tmp_path):
    tf = skip("CKV_AWS_18", "old skip")
    r = run(repo(tmp_path, "head", "\n\n\n" + tf), repo(tmp_path, "base", tf))
    assert r.returncode == 0, r.stderr


def test_changed_reason_counts_as_new(tmp_path):
    r = run(repo(tmp_path, "head", skip("CKV_AWS_18", "new words")), repo(tmp_path, "base", skip("CKV_AWS_18", "old words")))
    assert r.returncode == 1
    assert "doesn't cite" in r.stderr


@pytest.mark.parametrize("check,reason,msg", [
    ("CKV_AWS_18", "", "no reason"),
    ("CKV_AWS_18", "because", "doesn't cite"),
    ("CKV_AWS_18", "exceptions.yml#missing", "isn't in exceptions.yml"),
    ("CKV_AWS_18", "exceptions.yml#log-retention", "doesn't name CKV_AWS_18"),
    ("CKV_AWS_18", "exceptions.yml#forever", "within a year, not 'none'"),
    ("CKV_AWS_18", "exceptions.yml#too-far", "more than a year out"),
    ("CKV_AWS_18", "exceptions.yml#gone", "expired on 2026-01-01"),
    ("CKV_AWS_18", "exceptions.yml#pending", "not active"),
    ("CKV_AWS_117", "exceptions.yml#log-retention", "org baseline"),
])
def test_new_skip_failures(tmp_path, check, reason, msg):
    r = run(repo(tmp_path, "head", skip(check, reason)), repo(tmp_path, "base", ""))
    assert r.returncode == 1
    assert msg in r.stderr
    assert "envs/dev/main.tf:2" in r.stderr


def test_failure_message_never_echoes_the_reason(tmp_path):
    r = run(repo(tmp_path, "head", skip("CKV_AWS_18", "SECRET-ISH TEXT")), repo(tmp_path, "base", ""))
    assert "SECRET-ISH" not in r.stderr + r.stdout


def test_no_exceptions_file_fails_a_new_skip(tmp_path):
    head = repo(tmp_path, "head", skip("CKV_AWS_18", "exceptions.yml#x"), exceptions=None)
    r = run(head, repo(tmp_path, "base", ""))
    assert r.returncode == 1


def test_missing_base_dir_treats_every_skip_as_new(tmp_path):
    head = repo(tmp_path, "head", skip("CKV_AWS_18", "nothing"))
    r = run(head, tmp_path / "nope")
    assert r.returncode == 1


def test_terraform_cache_is_ignored(tmp_path):
    head = repo(tmp_path, "head", "")
    (head / ".terraform" / "modules").mkdir(parents=True)
    (head / ".terraform" / "modules" / "m.tf").write_text(skip("CKV_AWS_18", "vendored"))
    r = run(head, repo(tmp_path, "base", ""))
    assert r.returncode == 0, r.stderr
