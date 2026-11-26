# ABOUTME: Tests for checkov_skip_list.py: the shipped baseline parses, a repo's own skip-check
# ABOUTME: list is kept and merged without duplicates, and malformed files fail by name.
"""reusable-iac-checks.yml's checkov job passes this script's output as checkov-action's
skip_check, which replaces the repo's .checkov.yaml skip-check list, so the merge must keep it."""
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
SCRIPT = HERE / "checkov_skip_list.py"
FIX = HERE / "fixtures" / "checkov_skip_list"
BASELINE = ROOT / "policy" / "checkov" / "baseline.yaml"
sys.path.insert(0, str(HERE))
import checkov_skip_list as s  # noqa: E402

SHIPPED = ["CKV_AWS_117", "CKV_AWS_272", "CKV_AWS_144", "CKV2_AWS_62", "CKV_AWS_338"]


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_shipped_baseline_is_the_four_approved_checks():
    assert s.baseline_ids(BASELINE) == SHIPPED


def test_every_shipped_entry_names_a_standard_file():
    import yaml
    for entry in yaml.safe_load(BASELINE.read_text())["checks"]:
        assert entry["standard"].split("#")[0].endswith(".md")


def test_repo_skips_are_kept_after_the_baseline_without_duplicates():
    r = run("--baseline", str(BASELINE), "--repo-config", str(FIX / "repo.checkov.yaml"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().split(",") == SHIPPED + ["CKV_AWS_158"]


@pytest.mark.parametrize("cfg", ["no-skips.checkov.yaml", "does-not-exist.yaml"])
def test_repo_without_skips_gets_the_baseline(cfg):
    r = run("--baseline", str(BASELINE), "--repo-config", str(FIX / cfg))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().split(",") == SHIPPED


def test_comma_string_skip_check_is_accepted(tmp_path):
    cfg = tmp_path / ".checkov.yaml"
    cfg.write_text("skip-check: CKV_AWS_338, CKV2_AWS_8\n")
    assert s.repo_ids(cfg) == ["CKV_AWS_338", "CKV2_AWS_8"]


def test_entry_that_is_not_a_check_id_fails_without_echoing_it():
    r = run("--baseline", str(BASELINE), "--repo-config", str(FIX / "bad-id.checkov.yaml"))
    assert r.returncode == 1
    assert "not a check id" in r.stderr
    assert "rm -rf" not in r.stderr + r.stdout


def test_baseline_entry_without_a_reason_fails():
    r = run("--baseline", str(FIX / "baseline-missing-reason.yaml"))
    assert r.returncode == 1
    assert "checks[0]" in r.stderr
