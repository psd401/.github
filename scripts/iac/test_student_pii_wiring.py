# ABOUTME: Checks, on the YAML and by running steps with stubs, that the IaC reusable feeds the
# ABOUTME: student-pii rules: the plan job derives student-pii-account.json, conftest reads it from the artifact.
"""standards/08-iac.md 'Student PII account posture' and 'Student PII downgrade'.
account_controls.rego and unmask.rego deny an account-baseline root when
student-pii-account.json is missing, so a wiring slip fails that root rather
than passing it. These tests catch the slip before a caller sees it."""
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
IAC = ROOT / ".github/workflows/reusable-iac-checks.yml"


def jobs(path):
    return yaml.safe_load(path.read_text())["jobs"]


def step(steps, text, what):
    hits = [i for i, s in enumerate(steps) if text in (s.get("run") or "")]
    assert hits, f"no step {what}"
    return hits[0], steps[hits[0]]


def stub(directory, name, body):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(f"#!/bin/sh\n{body}\n")
    (directory / name).chmod(0o755)


def run_block(run, tmp_path, cwd=None, env=None, stubs=None):
    """Runs a step's run: block with the flags GitHub's bash shell uses, stubs first on PATH."""
    for name, body in (stubs or {}).items():
        stub(tmp_path / "bin", name, body)
    full_env = {"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin", "TMPDIR": str(tmp_path), **(env or {})}
    return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", run],
                          cwd=cwd or tmp_path, env=full_env, capture_output=True, text=True)


def data_args(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--data"]


def aws_conftest_argv(tmp_path, artifact, platform="aws"):
    """Runs the conftest job's conftest step with a stub conftest and returns its argv.
    `artifact` files sit in $RUNNER_TEMP/plan. Forged copies of every derived file
    sit in the caller checkout, which the step must not read."""
    _, s = step(jobs(IAC)["conftest"]["steps"], "conftest test", "running conftest on the plan")
    plan, workspace = tmp_path / "runner-temp" / "plan", tmp_path / "workspace"
    workspace.mkdir()
    for root, names in ((plan, ("tfplan.json", *artifact)),
                        (workspace, ("envs/dev/tfplan.json", "envs/dev/student-pii-account.json"))):
        for name in names:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text("{}")
    argv = tmp_path / "argv"
    result = run_block(s["run"], tmp_path, cwd=workspace,
                       env={"RUNNER_TEMP": str(plan.parent), "ARGV_OUT": str(argv),
                            "WORKING_DIRECTORY": "envs/dev", "PLATFORM": platform},
                       stubs={"conftest": 'printf "%s\\n" "$@" > "$ARGV_OUT"'})
    assert result.returncode == 0, result.stderr
    return argv.read_text().splitlines(), plan


def test_plan_job_derives_the_student_pii_account_file():
    _, resolve = step(jobs(IAC)["plan"]["steps"], "resolve_env_file.py", "resolving the env file")
    assert "--student-pii-out student-pii-account.json" in resolve["run"]


def test_plan_job_deletes_committed_derived_files_before_deriving_them(tmp_path):
    """A caller could commit a forged student-pii-account.json next to its
    Terraform, and the upload would carry it whenever a step did not overwrite it."""
    names = ("tfplan.json", "student-pii-account.json")
    steps = jobs(IAC)["plan"]["steps"]
    r, _ = step(steps, "resolve_env_file.py", "resolving the env file")
    hits = [s for s in steps[:r] if "rm -f" in (s.get("run") or "")]
    assert hits, "no step before the resolver deletes committed derived files"
    for name in names:
        (tmp_path / name).write_text("{}")
    result = run_block(hits[0]["run"], tmp_path)
    assert result.returncode == 0, result.stderr
    assert [n for n in names if (tmp_path / n).exists()] == []


def test_plan_artifact_carries_the_student_pii_account_file():
    steps = jobs(IAC)["plan"]["steps"]
    uploads = [s for s in steps if (s.get("uses") or "").startswith("actions/upload-artifact")]
    paths = uploads[0]["with"]["path"]
    assert "/tfplan.json" in paths and "/student-pii-account.json" in paths


def test_conftest_job_downloads_the_plan_artifact_outside_the_caller_checkout():
    """A file the caller committed survives a download over its checkout whenever
    the artifact lacks that file. $RUNNER_TEMP is outside the checkout."""
    steps = jobs(IAC)["conftest"]["steps"]
    downloads = [s for s in steps if (s.get("uses") or "").startswith("actions/download-artifact")]
    assert [d["with"]["path"] for d in downloads] == ["${{ runner.temp }}/plan"]


def test_aws_conftest_reads_the_plan_and_the_account_file_from_the_artifact(tmp_path):
    argv, plan = aws_conftest_argv(tmp_path, ("student-pii-account.json",))
    assert argv[:2] == ["test", f"{plan}/tfplan.json"]
    assert f"{plan}/student-pii-account.json" in data_args(argv)
    assert not [a for a in argv if "envs/dev" in a], "nothing is read from the caller checkout"


def test_aws_conftest_passes_the_account_file_only_when_the_artifact_holds_it(tmp_path):
    """conftest exits with a loader error on a --data path that does not exist,
    which would hide account_controls.rego's 'data.student_pii_account is missing' deny."""
    argv, plan = aws_conftest_argv(tmp_path, ())
    assert argv[:2] == ["test", f"{plan}/tfplan.json"]
    assert not [d for d in data_args(argv) if d.endswith("student-pii-account.json")]


def test_aws_conftest_reads_the_telemetry_layer_list(tmp_path):
    """student_pii_destinations.rego fails closed on any student-pii Lambda
    with layers when data.telemetry_layers is missing."""
    argv, _ = aws_conftest_argv(tmp_path, ("student-pii-account.json",))
    assert "_policy/policy/data/telemetry-layers.yml" in data_args(argv)


def test_gcp_conftest_reads_only_the_exceptions_file(tmp_path):
    argv, plan = aws_conftest_argv(tmp_path, ("student-pii-account.json",), platform="gcp")
    assert argv[:2] == ["test", f"{plan}/tfplan.json"]
    assert data_args(argv) == ["exceptions.yml"]


def test_aws_conftest_runs_the_downgrade_check_on_the_redacted_plan_after_the_cross_check():
    steps = jobs(IAC)["conftest"]["steps"]
    cross, _ = step(steps, "check_exceptions.py", "running check_exceptions.py")
    i, s = step(steps, "check_classification_downgrade.py", "running check_classification_downgrade.py")
    assert i > cross, "the cross-check installs pyyaml and jsonschema, which the downgrade check imports"
    assert '--plan-json "$RUNNER_TEMP/plan/tfplan.json"' in s["run"]
    assert "--exceptions exceptions.yml" in s["run"]
    assert "inputs.platform == 'aws'" in s["if"]
