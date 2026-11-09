# ABOUTME: Static checks on reusable-iac-checks.yml and reusable-onprem-checks.yml: every helper
# ABOUTME: checkout is this repo at the pinned SHA, and every pip install is hash-locked.
"""Inside a called reusable, the caller's GITHUB_TOKEN can read only the
caller's repo, so a helper checkout of any other private repo 404s. These
reusables check out this (public) repo instead, at the SHA the caller pinned.
job.workflow_repository and job.workflow_sha are "the owner/repo of the
repository containing the workflow file that defines the current job" and
"the commit SHA of the workflow file that defines the current job"
(https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context,
read 2026-11-06)."""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = [ROOT / ".github/workflows" / n for n in ("reusable-iac-checks.yml", "reusable-onprem-checks.yml")]
SELF_REPO = "${{ job.workflow_repository }}"
SELF_REF = "${{ inputs.tooling_ref || job.workflow_sha }}"
ENV_FILE_CHECK = "PSD401/.github/.github/workflows/reusable-env-file-check.yml@"
ENV_FILE_CHECK_PIN = re.compile(re.escape(ENV_FILE_CHECK) + r"[0-9a-f]{40} # v\d+\.\d+\.\d+")
HELPER_PATH = re.compile(r"\b(_[\w-]+)/((?:policy|schemas|scripts|tools)/[\w./-]*)")
ids = [w.name for w in WORKFLOWS]


def load(wf):
    return yaml.safe_load(wf.read_text())


def steps(job):
    return job.get("steps", [])


def is_checkout(step):
    return (step.get("uses") or "").startswith("actions/checkout@")


def helper_checkouts(job):
    return [s for s in steps(job) if is_checkout(s) and (s.get("with") or {}).get("repository")]


def sparse_paths(step):
    return [p.strip() for p in (step.get("with") or {}).get("sparse-checkout", "").splitlines() if p.strip()]


def covered(rel, paths):
    return any(rel == p or (p.endswith("/") and rel.startswith(p)) for p in paths)


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_no_reference_to_the_internal_standards_repo(wf):
    assert "psd-dev-standards" not in wf.read_text().lower()


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_tooling_ref_replaces_conftest_policy_ref_and_defaults_to_the_pinned_sha(wf):
    inputs = load(wf)["on"]["workflow_call"]["inputs"]
    assert "conftest_policy_ref" not in inputs
    assert inputs["tooling_ref"]["default"] == ""
    assert inputs["tooling_ref"]["required"] is False


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_every_helper_checkout_is_this_repo_at_the_pinned_sha(wf):
    found = 0
    for name, job in load(wf)["jobs"].items():
        for s in helper_checkouts(job):
            found += 1
            w = s["with"]
            assert w["repository"] == SELF_REPO, f"{name}: {s.get('name')}"
            assert w.get("ref") == SELF_REF, f"{name}: {s.get('name')}"
            assert w.get("persist-credentials") is False, f"{name}: {s.get('name')}"
            assert w.get("sparse-checkout-cone-mode") is False, f"{name}: {s.get('name')}"
    assert found, "expected helper checkouts"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_sparse_checkout_paths_exist_in_this_repo(wf):
    for name, job in load(wf)["jobs"].items():
        for s in helper_checkouts(job):
            paths = sparse_paths(s)
            assert paths, f"{name}: {s.get('name')} should be sparse"
            for p in paths:
                target = ROOT / p
                assert target.is_dir() if p.endswith("/") else target.is_file(), f"{name}: {p} missing"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_run_steps_read_only_files_their_job_checked_out(wf):
    for name, job in load(wf)["jobs"].items():
        by_path = {(s["with"].get("path") or ""): sparse_paths(s) for s in helper_checkouts(job)}
        for s in steps(job):
            for prefix, rel in HELPER_PATH.findall(s.get("run", "")):
                assert prefix in by_path, f"{name}: run reads {prefix}/{rel} but no checkout has path {prefix}"
                assert covered(rel, by_path[prefix]), f"{name}: {prefix}/{rel} is outside the sparse checkout"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_every_pip_install_requires_hashes_from_a_checked_out_lockfile(wf):
    installs = 0
    for name, job in load(wf)["jobs"].items():
        for s in steps(job):
            for line in s.get("run", "").splitlines():
                if not re.search(r"\bpip3?\b.*\binstall\b", line):
                    continue
                installs += 1
                assert "--require-hashes" in line, f"{name}: {line.strip()}"
                assert re.search(r"-r\s+\S*_[\w-]+/tools/iac/requirements[\w-]*\.txt", line), f"{name}: {line.strip()}"
    assert installs, "expected hash-locked installs"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_env_file_check_calls_this_repos_copy_at_a_release_pin(wf):
    """The parsed `uses:` drops the `# vX.Y.Z` comment, so read the raw line."""
    assert load(wf)["jobs"]["env-file-check"]["uses"].startswith(ENV_FILE_CHECK)
    lines = [ln.strip() for ln in wf.read_text().splitlines() if ln.strip().startswith(f"uses: {ENV_FILE_CHECK}")]
    assert len(lines) == 1, lines
    assert ENV_FILE_CHECK_PIN.fullmatch(lines[0].removeprefix("uses: ")), lines[0]


VALIDATE = "Validate tooling_ref"


def validation_steps(wf):
    return [s for job in load(wf)["jobs"].values() for s in steps(job) if s.get("name") == VALIDATE]


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_every_job_with_a_helper_checkout_validates_tooling_ref_first(wf):
    for name, job in load(wf)["jobs"].items():
        if not helper_checkouts(job):
            continue
        names = [s.get("name") for s in steps(job)]
        assert VALIDATE in names, f"{name}: no {VALIDATE} step"
        first_helper = next(i for i, s in enumerate(steps(job)) if is_checkout(s) and (s.get("with") or {}).get("repository"))
        assert names.index(VALIDATE) < first_helper, f"{name}: {VALIDATE} must run before the helper checkout"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=ids)
def test_tooling_ref_reaches_run_only_through_env(wf):
    for s in validation_steps(wf):
        assert s["env"] == {"TOOLING_REF": "${{ inputs.tooling_ref }}"}
        assert "${{" not in s["run"]
    for name, job in load(wf)["jobs"].items():
        for s in steps(job):
            assert "inputs.tooling_ref" not in s.get("run", ""), f"{name}: {s.get('name')}"


def test_validation_step_is_the_same_everywhere():
    scripts = {s["run"] for wf in WORKFLOWS for s in validation_steps(wf)}
    assert len(scripts) == 1, scripts


def test_tooling_ref_description_carries_the_trust_note():
    descs = {load(wf)["on"]["workflow_call"]["inputs"]["tooling_ref"]["description"] for wf in WORKFLOWS}
    assert len(descs) == 1
    assert "secrets" in descs.pop()


ACCEPTED = ["", "a" * 40, "0123456789abcdef0123456789abcdef01234567", "main", "feat/move-iac.v2_x",
            "refs/heads/main", "refs/heads/feat/x-y"]
REJECTED = ["-c", "--upload-pack=x", "a..b", "refs/tags/v1.0.0", "refs/pull/1/merge", "refs/heads/",
            "main;id", "$(id)", "`id`", "main x", " main", "main\nother", "ma*in", "refs/heads/a b"]


def run_validation(value):
    import subprocess
    import os
    script = validation_steps(WORKFLOWS[0])[0]["run"]
    env = {**os.environ, "TOOLING_REF": value}
    return subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("value", ACCEPTED, ids=repr)
def test_validation_accepts(value):
    r = run_validation(value)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("value", REJECTED, ids=repr)
def test_validation_rejects_without_echoing_the_value(value):
    r = run_validation(value)
    assert r.returncode != 0
    assert "::error::" in r.stdout
    fixed_message = run_validation("\x01").stdout
    if value.strip() and value.strip() not in fixed_message:
        assert value.strip() not in r.stdout + r.stderr
