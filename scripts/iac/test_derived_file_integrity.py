# ABOUTME: Checks, by running steps with stubs, that the IaC reusable writes the derived env-file data only on
# ABOUTME: aws, records each file's SHA-256 as a plan job output, and that conftest refuses a file that changed.
"""Caller code runs during terraform plan (a data "external" program, say) and
can rewrite student-pii-account.json or ses-from-addresses.json in
working_directory before the upload. A finished step's outputs can't be
rewritten, so the resolve step records each file's SHA-256 there and the
conftest job checks the artifact against them. Both files hold cloud.aws data,
so a gcp plan writes neither."""
import hashlib

from test_student_pii_wiring import IAC, jobs, run_block, step

DERIVED = ("student-pii-account.json", "ses-from-addresses.json")

SHA256_STUB = 'if command -v shasum >/dev/null; then exec shasum -a 256 "$@"; else exec /usr/bin/sha256sum "$@"; fi'

# Records its argv and writes each --student-pii-out / --ses-out file.
RESOLVER_STUB = r'''printf "%s\n" "$@" > "$ARGV_OUT"
while [ $# -gt 0 ]; do
  case "$1" in --student-pii-out|--ses-out) printf '{"from": "%s"}' "$1" > "$2"; shift ;; esac
  shift
done'''


def run_resolve(tmp_path, platform):
    _, s = step(jobs(IAC)["plan"]["steps"], "resolve_env_file.py", "resolving the env file")
    work = tmp_path / "work"
    work.mkdir()
    out, argv = tmp_path / "github_output", tmp_path / "argv"
    result = run_block(s["run"], tmp_path, cwd=work, env={
        "PSD_ENV_FILE_CONTENTS": "e30K", "PLATFORM": platform, "ENVIRONMENT": "dev",
        "ACCOUNT_ALIAS": "nonprod", "AWS_REGION": "us-west-2", "REPO_NAME": "app",
        "GITHUB_WORKSPACE": str(tmp_path), "GITHUB_ENV": str(tmp_path / "github_env"),
        "GITHUB_OUTPUT": str(out), "ARGV_OUT": str(argv)},
        stubs={"python3": RESOLVER_STUB, "sha256sum": SHA256_STUB})
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    return argv.read_text().splitlines(), outputs, work


def test_aws_plan_writes_both_derived_files_and_records_their_hashes(tmp_path):
    argv, outputs, work = run_resolve(tmp_path, "aws")
    assert "--student-pii-out" in argv and "--ses-out" in argv
    for key, name in (("student_pii_sha256", DERIVED[0]), ("ses_sha256", DERIVED[1])):
        assert outputs[key] == hashlib.sha256((work / name).read_bytes()).hexdigest()


def test_gcp_plan_writes_neither_derived_file(tmp_path):
    argv, outputs, work = run_resolve(tmp_path, "gcp")
    assert "--student-pii-out" not in argv and "--ses-out" not in argv
    assert not any((work / name).exists() for name in DERIVED)
    assert outputs == {"student_pii_sha256": "absent", "ses_sha256": "absent"}


def test_plan_job_exposes_the_hashes_from_the_resolve_step():
    plan = jobs(IAC)["plan"]
    resolve = [s for s in plan["steps"] if "resolve_env_file.py" in (s.get("run") or "")][0]
    assert resolve["id"] == "resolve"
    assert plan["outputs"]["student_pii_sha256"] == "${{ steps.resolve.outputs.student_pii_sha256 }}"
    assert plan["outputs"]["ses_sha256"] == "${{ steps.resolve.outputs.ses_sha256 }}"


def run_check(tmp_path, files, want_pii, want_ses):
    steps = jobs(IAC)["conftest"]["steps"]
    i, s = step(steps, "WANT_STUDENT_PII", "checking the derived files' hashes")
    c, _ = step(steps, "conftest test", "running conftest on the plan")
    assert i < c, "the hash check must run before conftest reads the files"
    plan = tmp_path / "runner-temp" / "plan"
    plan.mkdir(parents=True)
    for name, body in files.items():
        (plan / name).write_text(body)
    return run_block(s["run"], tmp_path, env={
        "RUNNER_TEMP": str(plan.parent), "WANT_STUDENT_PII": want_pii, "WANT_SES": want_ses},
        stubs={"sha256sum": SHA256_STUB})


def sha(body):
    return hashlib.sha256(body.encode()).hexdigest()


def test_conftest_accepts_the_files_the_resolve_step_wrote(tmp_path):
    result = run_check(tmp_path, {DERIVED[0]: "a", DERIVED[1]: "b"}, sha("a"), sha("b"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_conftest_accepts_absent_files_the_resolve_step_did_not_write(tmp_path):
    result = run_check(tmp_path, {}, "absent", "absent")
    assert result.returncode == 0, result.stdout + result.stderr


def test_conftest_refuses_a_rewritten_file(tmp_path):
    result = run_check(tmp_path, {DERIVED[0]: "a", DERIVED[1]: "forged"}, sha("a"), sha("b"))
    assert result.returncode != 0
    assert "ses-from-addresses.json in the plan artifact is not the file the resolve step wrote" in result.stdout


def test_conftest_refuses_a_file_the_resolve_step_did_not_write(tmp_path):
    result = run_check(tmp_path, {DERIVED[1]: "planted"}, "absent", "absent")
    assert result.returncode != 0


def test_conftest_refuses_when_no_hash_was_recorded(tmp_path):
    result = run_check(tmp_path, {DERIVED[0]: "a"}, "", "absent")
    assert result.returncode != 0
