# ABOUTME: Checks, on the YAML and by running steps with stubs, that the IaC reusable feeds ses_send.rego:
# ABOUTME: the plan job derives ses-from-addresses.json, conftest reads it from the artifact.
"""17-email-sending.md rules 3 and 9. ses_send.rego denies a statement that pins
ses:FromAddress when data.ses_from_addresses is missing, so a wiring slip fails
every SES-sending root rather than passing it. These tests catch the slip
before a caller sees it."""
from test_student_pii_wiring import IAC, aws_conftest_argv, data_args, jobs, run_block, step


def test_plan_job_derives_the_ses_from_addresses_file():
    _, resolve = step(jobs(IAC)["plan"]["steps"], "resolve_env_file.py", "resolving the env file")
    assert "--ses-out ses-from-addresses.json" in resolve["run"]


def test_plan_job_deletes_a_committed_ses_file_before_deriving_it(tmp_path):
    """A caller could commit a forged ses-from-addresses.json next to its
    Terraform, and the upload would carry it whenever a step did not overwrite it."""
    steps = jobs(IAC)["plan"]["steps"]
    r, _ = step(steps, "resolve_env_file.py", "resolving the env file")
    hits = [s for s in steps[:r] if "rm -f" in (s.get("run") or "")]
    assert hits, "no step before the resolver deletes committed derived files"
    (tmp_path / "ses-from-addresses.json").write_text("{}")
    result = run_block(hits[0]["run"], tmp_path)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "ses-from-addresses.json").exists()


def test_plan_artifact_carries_the_ses_file():
    steps = jobs(IAC)["plan"]["steps"]
    uploads = [s for s in steps if (s.get("uses") or "").startswith("actions/upload-artifact")]
    assert "/ses-from-addresses.json" in uploads[0]["with"]["path"]


def test_aws_conftest_reads_the_ses_file_from_the_artifact(tmp_path):
    argv, plan = aws_conftest_argv(tmp_path, ("student-pii-account.json", "ses-from-addresses.json"))
    assert f"{plan}/ses-from-addresses.json" in data_args(argv)
    assert not [a for a in argv if "envs/dev" in a], "nothing is read from the caller checkout"


def test_aws_conftest_passes_the_ses_file_only_when_the_artifact_holds_it(tmp_path):
    """conftest exits with a loader error on a --data path that does not exist,
    which would hide ses_send.rego's 'data.ses_from_addresses is missing' deny."""
    argv, _ = aws_conftest_argv(tmp_path, ("student-pii-account.json",))
    assert not [d for d in data_args(argv) if d.endswith("ses-from-addresses.json")]


def test_gcp_conftest_does_not_read_the_ses_file(tmp_path):
    argv, _ = aws_conftest_argv(tmp_path, ("ses-from-addresses.json",), platform="gcp")
    assert data_args(argv) == ["exceptions.yml"]
