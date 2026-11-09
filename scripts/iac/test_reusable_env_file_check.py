# ABOUTME: Static checks on reusable-env-file-check.yml: it checks out this repo at the SHA
# ABOUTME: the caller pinned, reads only files that exist here, and installs only hash-locked deps.
"""A caller pins the reusable by SHA. A checkout with no ref (or ref main)
would run main's schema inside the pinned workflow, and a checkout of any
other repo 404s for callers whose GITHUB_TOKEN can't read it.
job.workflow_repository and job.workflow_sha are "the owner/repo of the
repository containing the workflow file that defines the current job" and
"the commit SHA of the workflow file that defines the current job"
(https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context,
read 2026-11-06)."""
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/reusable-env-file-check.yml"
TEXT = WORKFLOW.read_text()
DOC = yaml.safe_load(TEXT)
STEPS = [s for job in DOC["jobs"].values() for s in job.get("steps", [])]
CHECKOUTS = [s for s in STEPS if (s.get("uses") or "").startswith("actions/checkout@")]


def sparse_paths(step):
    return [p.strip() for p in (step.get("with") or {}).get("sparse-checkout", "").splitlines() if p.strip()]


def test_has_a_self_checkout():
    assert CHECKOUTS, "expected a checkout of this repo's schema"


def test_every_checkout_is_this_repo_at_the_pinned_sha():
    for step in CHECKOUTS:
        w = step.get("with") or {}
        assert w.get("repository") == "${{ job.workflow_repository }}", step.get("name")
        assert w.get("ref") == "${{ job.workflow_sha }}", step.get("name")
        assert w.get("persist-credentials") is False, step.get("name")


def test_sparse_checkout_paths_exist_in_this_repo():
    for step in CHECKOUTS:
        paths = sparse_paths(step)
        assert paths, f"{step.get('name')}: checkout should be sparse"
        for p in paths:
            assert (ROOT / p).is_file(), f"{step.get('name')}: {p} is not a file in this repo"


def test_run_steps_read_only_checked_out_files():
    # Every repo-relative path a run step names must be in a sparse checkout.
    checked_out = {p for s in CHECKOUTS for p in sparse_paths(s)}
    runs = "\n".join(s.get("run", "") for s in STEPS)
    for p in re.findall(r"\b(?:schemas|tools|scripts)/[\w./-]+", runs):
        assert p in checked_out, f"run step reads {p}, which no checkout fetches"


def test_every_pip_install_requires_hashes():
    runs = [s.get("run", "") for s in STEPS]
    installs = [line for r in runs for line in r.splitlines() if re.search(r"\bpip\b.*\binstall\b", line)]
    assert installs, "expected a pip install of the validator deps"
    for line in installs:
        assert "--require-hashes" in line, line
        assert re.search(r"-r\s+\S*tools/iac/requirements\.txt", line), line
