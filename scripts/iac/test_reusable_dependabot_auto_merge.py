# ABOUTME: Tests for reusable-dependabot-auto-merge.yml. Each run step executes under bash -e against
# ABOUTME: a fake gh first on PATH, with the real jq, so the merge decision is tested as behavior.
"""Standard 04-security rule 4: auto-merge patch-level dev-dependency PRs when
CI is green, nothing else auto-merges. Each behavior test pulls one step's
run: script out of the workflow and runs it the way Actions does (bash -e,
no pipefail). The fake gh answers from canned JSON in env vars, applies the
--jq filter with the real jq once per page as gh --paginate does, and logs
every call. The step's env: values are resolved from the expressions the
workflow wires in, so a test fails if that wiring changes.

Response shapes are from read-only calls on 2026-11-20: rules/branches from
psd401/santa-sync and psd401/psd-jamf-infra (active required_status_checks
rules), branches/main from psd401/pingtool (classic required checks) and
psd401/psd-eoc (none)."""
import functools
import json
import os
import pathlib
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/reusable-dependabot-auto-merge.yml"
FETCH_METADATA = "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98"
HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
PR_URL = "https://github.com/psd401/example/pull/7"
PATCH = "version-update:semver-patch"
DEV = "direct:development"
METHODS = ["merge", "squash", "rebase"]

# Every expression the job's env: blocks may use, by a short name the tests pass.
EXPR = {
    "token": "${{ github.token }}",
    "merge_method": "${{ inputs.merge_method }}",
    "base_ref": "${{ github.event.pull_request.base.ref }}",
    "pr": "${{ github.event.pull_request.number }}",
    "pr_url": "${{ github.event.pull_request.html_url }}",
    "head_sha": "${{ github.event.pull_request.head.sha }}",
    "updates": "${{ steps.metadata.outputs.updated-dependencies-json }}",
    "psd_pins": "${{ inputs.psd_reusable_pins }}",
}
DEFAULTS = {"token": "fake-token", "merge_method": "squash", "base_ref": "main", "pr": "7",
            "pr_url": PR_URL, "head_sha": HEAD_SHA, "updates": "[]", "psd_pins": "false"}

# Answers gh api from FAKE_<NAME> (a stream of JSON pages) or fails on FAKE_FAIL_<NAME>=1.
# Without --paginate it serves only the first page, like gh.
FAKE_GH = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GH_LOG"
if [ "$1" = pr ]; then
  if [ "${FAKE_FAIL_PR:-}" = 1 ]; then echo "fake gh: pr failed" >&2; exit 1; fi
  exit 0
fi
if [ "$1" != api ]; then echo "fake gh: unexpected command $1" >&2; exit 2; fi
shift
path="" filter="." paginate=0
while [ $# -gt 0 ]; do
  case "$1" in
    --jq | -q) filter=$2; shift 2 ;;
    --paginate) paginate=1; shift ;;
    -*) echo "fake gh: unexpected flag $1" >&2; exit 2 ;;
    *) path=$1; shift ;;
  esac
done
case "$path" in
  repos/*/rules/branches/*) name=RULES ;;
  repos/*/branches/*) name=BRANCH ;;
  repos/*/pulls/*/commits) name=COMMITS ;;
  repos/*/pulls/*) name=PULL ;;
  *) echo "fake gh: unexpected path $path" >&2; exit 2 ;;
esac
fail_var=FAKE_FAIL_$name
resp_var=FAKE_$name
if [ "${!fail_var:-}" = 1 ]; then echo "gh: Server Error (HTTP 500)" >&2; exit 1; fi
resp=${!resp_var:-}
if [ -z "$resp" ]; then echo "fake gh: no canned $resp_var" >&2; exit 2; fi
if [ "$paginate" = 0 ]; then resp=$(jq -c -n input <<<"$resp"); fi
jq -r "$filter" <<<"$resp"
"""


@functools.cache
def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def job():
    (only,) = workflow()["jobs"].values()
    return only


def step(step_id):
    found = [s for s in job()["steps"] if s.get("id") == step_id]
    assert len(found) == 1, f"expected one step with id {step_id}"
    return found[0]


def run_scripts():
    return [s["run"] for s in job()["steps"] if "run" in s]


def pages(*arrays):
    return "\n".join(json.dumps(a) for a in arrays)


def require_jq():
    if shutil.which("jq") is None:
        pytest.fail("jq is not on PATH. These tests run the workflow's jq filters with the real jq: install it.")


def run_step(step_id, tmp_path, gh=None, **values):
    """Run one step's run: script with bash -e. gh maps fake names (RULES,
    FAIL_RULES, PR, FAIL_PR, ...) to FAKE_<name> env vars."""
    require_jq()
    s = step(step_id)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "gh"
    fake.write_text(FAKE_GH)
    fake.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(s["run"])
    files = {n: tmp_path / n for n in ("output", "summary", "gh.log")}
    for f in files.values():
        f.write_text("")
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GITHUB_OUTPUT": str(files["output"]),
        "GITHUB_STEP_SUMMARY": str(files["summary"]),
        "GITHUB_REPOSITORY": "psd401/example",
        "FAKE_GH_LOG": str(files["gh.log"]),
    }
    by_expr = {v: k for k, v in EXPR.items()}
    for var, expr in (s.get("env") or {}).items():
        assert expr in by_expr, f"{step_id}: env {var} uses {expr}, which these tests don't model"
        name = by_expr[expr]
        env[var] = values.get(name, DEFAULTS[name])
    for k, v in (gh or {}).items():
        env[f"FAKE_{k}"] = v
    proc = subprocess.run(["bash", "-e", str(script)], env=env, capture_output=True, text=True, timeout=30)
    outputs = dict(line.split("=", 1) for line in files["output"].read_text().splitlines() if "=" in line)
    calls = files["gh.log"].read_text().splitlines()
    return SimpleNamespace(rc=proc.returncode, out=proc.stdout + proc.stderr, outputs=outputs,
                           summary=files["summary"].read_text(), calls=calls,
                           pr_calls=[c for c in calls if c.startswith("pr ")])


def one_line(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return len(lines) == 1


# --- canned API responses -------------------------------------------------

def rule(rule_type, **parameters):
    r = {"type": rule_type, "ruleset_source_type": "Repository", "ruleset_source": "psd401/example",
         "ruleset_id": 15369760}
    if parameters:
        r["parameters"] = parameters
    return r


ORG_RULES = [rule("deletion"), rule("non_fast_forward")]
CHECK_RULE = rule("required_status_checks", strict_required_status_checks_policy=False,
                  do_not_enforce_on_create=False, required_status_checks=[{"context": "psd-ci / psd-ci"}])


def branch(level="off", contexts=()):
    return {"name": "main", "protected": True, "protection": {
        "enabled": level != "off",
        "required_status_checks": {"enforcement_level": level, "contexts": list(contexts),
                                   "checks": [{"context": c, "app_id": 15368} for c in contexts]}}}


def commit(sha, login="dependabot[bot]", verified=True):
    return {"sha": sha, "author": None if login is None else {"login": login, "type": "Bot"},
            "committer": {"login": "web-flow"},
            "commit": {"verification": {"verified": verified, "reason": "valid" if verified else "unsigned"}}}


def dep(name="eslint", update=PATCH, dtype=DEV):
    return {"dependencyName": name, "dependencyType": dtype, "updateType": update, "directory": "/",
            "packageEcosystem": "npm_and_yarn", "targetBranch": "", "prevVersion": "9.0.0",
            "newVersion": "9.0.1", "compatScore": 0, "maintainerChanges": False, "dependencyGroup": "",
            "alertState": "", "ghsaId": "", "cvss": 0}


MINOR = "version-update:semver-minor"
PSD_CI = "PSD401/.github/.github/workflows/reusable-psd-ci.yml"


def pin(name=PSD_CI, update=MINOR, ecosystem="github_actions"):
    """A github-actions update as fetch-metadata reports it. Dependabot types
    every one direct:production: psd401/psd-eoc#709 (reusable-psd-ci.yml 1.5.0
    to 1.7.0, semver-minor), and the astral-sh/setup-uv update in
    psd401/blockfinder run 45825313712, read 2026-11-26."""
    return {"dependencyName": name, "dependencyType": "direct:production", "updateType": update,
            "directory": "/", "packageEcosystem": ecosystem, "targetBranch": "main", "prevVersion": "1.5.0",
            "newVersion": "1.7.0", "compatScore": 0, "maintainerChanges": False, "dependencyGroup": "",
            "alertState": "", "ghsaId": "", "cvss": 0}


# --- merge_method validation ---------------------------------------------

def test_merge_method_is_checked_first():
    assert job()["steps"][0].get("id") == "method"


@pytest.mark.parametrize("method", METHODS)
def test_merge_method_accepts(method, tmp_path):
    r = run_step("method", tmp_path, merge_method=method)
    assert r.rc == 0, r.out


@pytest.mark.parametrize("method", ["", "Squash", "fast-forward", "admin", "--admin", "squash --admin",
                                    "squash\nrebase", "$(id)"], ids=repr)
def test_merge_method_rejects(method, tmp_path):
    r = run_step("method", tmp_path, merge_method=method)
    assert r.rc != 0
    assert "::error::" in r.out


# --- gate: the base branch enforces a required status check --------------

@pytest.mark.parametrize("rules,protection", [
    (pages(ORG_RULES + [CHECK_RULE]), branch()),
    (pages([rule("deletion")] * 30, [CHECK_RULE]), branch()),
    (pages(ORG_RULES), branch("everyone", ["psd-ci / psd-ci"])),
    (pages(ORG_RULES), branch("non_admins", ["psd-ci / psd-ci"])),
], ids=["ruleset", "ruleset rule on page 2", "classic everyone", "classic non_admins"])
def test_gate_enforced(rules, protection, tmp_path):
    r = run_step("gate", tmp_path, gh={"RULES": rules, "BRANCH": json.dumps(protection)})
    assert r.rc == 0, r.out
    assert r.outputs.get("enforced") == "true"


@pytest.mark.parametrize("rules,protection", [
    (pages(ORG_RULES), branch()),
    (pages([]), {"name": "main", "protected": False}),
    (pages(ORG_RULES + [rule("required_status_checks", required_status_checks=[])]), branch()),
    (pages(ORG_RULES), branch("off", ["psd-ci / psd-ci"])),
    (pages(ORG_RULES), branch("everyone", [])),
], ids=["neither", "unprotected", "ruleset rule with no checks", "classic contexts but enforcement off",
        "classic enforcement but no checks"])
def test_gate_not_enforced_leaves_the_pr_and_succeeds(rules, protection, tmp_path):
    r = run_step("gate", tmp_path, gh={"RULES": rules, "BRANCH": json.dumps(protection)})
    assert r.rc == 0, r.out
    assert r.outputs.get("enforced") == "false"
    assert "::warning::" in r.out
    assert one_line(r.summary), r.summary


@pytest.mark.parametrize("failing", ["FAIL_RULES", "FAIL_BRANCH"])
def test_gate_api_failure_fails_the_step(failing, tmp_path):
    gh = {"RULES": pages(ORG_RULES + [CHECK_RULE]), "BRANCH": json.dumps(branch("everyone", ["x"])), failing: "1"}
    r = run_step("gate", tmp_path, gh=gh)
    assert r.rc != 0
    assert "enforced" not in r.outputs


# --- provenance: Dependabot wrote and GitHub verified every commit --------

def test_provenance_all_dependabot_and_verified(tmp_path):
    r = run_step("provenance", tmp_path, gh={"COMMITS": pages([commit("a1"), commit("a2")])})
    assert r.rc == 0, r.out
    assert r.outputs.get("dependabot") == "true"


@pytest.mark.parametrize("commits", [
    pages([commit("a1"), commit("b2", login="octocat")]),
    pages([commit("a1"), commit("b2", verified=False)]),
    pages([commit("a1"), commit("b2", login=None)]),
    pages([commit(f"a{i}") for i in range(30)], [commit("b2", login="octocat")]),
], ids=["foreign author", "unverified", "author with no account", "offender on page 2"])
def test_provenance_rejects(commits, tmp_path):
    r = run_step("provenance", tmp_path, gh={"COMMITS": commits})
    assert r.rc == 0, r.out
    assert r.outputs.get("dependabot") == "false"
    assert "b2" in r.out
    assert one_line(r.summary), r.summary


def test_provenance_api_failure_fails_the_step(tmp_path):
    r = run_step("provenance", tmp_path, gh={"COMMITS": pages([commit("a1")]), "FAIL_COMMITS": "1"})
    assert r.rc != 0
    assert "dependabot" not in r.outputs


# --- decision: every update is a patch to a direct dev dependency ---------

@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("updates", [[dep()], [dep("eslint"), dep("prettier"), dep("vitest")]],
                         ids=["one patch dev dep", "group of patch dev deps"])
def test_decision_merges(updates, method, tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps(updates), merge_method=method)
    assert r.rc == 0, r.out
    assert r.outputs.get("merge") == "true"
    assert len(r.pr_calls) == 1, r.calls
    args = r.pr_calls[0].split()
    assert args[:2] == ["pr", "merge"]
    assert "--auto" in args
    assert f"--{method}" in args
    assert not ({"--merge", "--squash", "--rebase", "--admin"} - {f"--{method}"}) & set(args)
    assert args[args.index("--match-head-commit") + 1] == HEAD_SHA
    assert PR_URL in args
    assert one_line(r.summary), r.summary


@pytest.mark.parametrize("updates", [
    json.dumps([dep("eslint"), dep("vite", update="version-update:semver-minor")]),
    json.dumps([dep(dtype="direct:production")]),
    json.dumps([dep(dtype="indirect")]),
    json.dumps([dep(update="version-update:semver-major")]),
    json.dumps([dep(update=None)]),
    json.dumps([{"dependencyName": "eslint", "updateType": PATCH}]),
    "[]",
    "",
    "[{",
    "null",
    json.dumps(dep()),
    json.dumps([PATCH, DEV]),
], ids=["group with one minor", "patch production", "indirect", "major", "null updateType",
        "missing dependencyType", "empty array", "empty output", "malformed", "null", "object not array",
        "array of strings"])
def test_decision_does_not_merge(updates, tmp_path):
    r = run_step("decide", tmp_path, updates=updates)
    assert r.rc == 0, r.out
    assert r.outputs.get("merge") == "false"
    assert r.pr_calls == []
    assert one_line(r.summary), r.summary


# --- psd_reusable_pins: patch and minor bumps of this repo's reusables -----

PIN_MERGES = {
    "minor": [pin()],
    "patch": [pin(update=PATCH)],
    "lower-case owner": [pin("psd401/.github/.github/workflows/reusable-security-scan.yml")],
    "group of pins": [pin(), pin(PSD_CI.replace("psd-ci", "claude-review"), PATCH),
                      pin(PSD_CI.replace("psd-ci", "security-scan"))],
}


@pytest.mark.parametrize("updates", PIN_MERGES.values(), ids=PIN_MERGES.keys())
def test_reusable_pins_merge_with_the_input_on(updates, tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps(updates), psd_pins="true")
    assert r.rc == 0, r.out
    assert r.outputs.get("merge") == "true"
    assert len(r.pr_calls) == 1, r.calls
    args = r.pr_calls[0].split()
    assert "--auto" in args and "--squash" in args and "--admin" not in args
    assert args[args.index("--match-head-commit") + 1] == HEAD_SHA
    assert one_line(r.summary), r.summary
    assert "PSD401/.github reusable" in r.summary


@pytest.mark.parametrize("updates", PIN_MERGES.values(), ids=PIN_MERGES.keys())
@pytest.mark.parametrize("value", ["false", "", "True", "1", "yes"])
def test_reusable_pins_do_not_merge_unless_the_input_is_exactly_true(updates, value, tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps(updates), psd_pins=value)
    assert r.rc == 0, r.out
    assert r.outputs.get("merge") == "false"
    assert r.pr_calls == []
    assert one_line(r.summary), r.summary


PIN_REFUSED = {
    "major": [pin(update="version-update:semver-major")],
    "null updateType": [pin(update=None)],
    "another action": [pin("astral-sh/setup-uv")],
    "pin grouped with another action": [pin(), pin("astral-sh/setup-uv")],
    "pin grouped with a minor dev dep": [pin(), dep(update=MINOR)],
    "look-alike repo": [pin("PSD401/.github-evil/.github/workflows/reusable-x.yml")],
    "look-alike owner": [pin("notPSD401/.github/.github/workflows/reusable-x.yml")],
    "owner as a path prefix": [pin("x/PSD401/.github/.github/workflows/reusable-x.yml")],
    "a workflow here that is not a reusable": [pin("PSD401/.github/.github/workflows/release.yml")],
    "an action in this repo, not a workflow": [pin("PSD401/.github/actions/reusable-x")],
    "pin name in another ecosystem": [pin(ecosystem="npm_and_yarn")],
    "missing ecosystem": [{k: v for k, v in pin().items() if k != "packageEcosystem"}],
    "missing name": [{k: v for k, v in pin().items() if k != "dependencyName"}],
    "null name": [dict(pin(), dependencyName=None)],
    "name not a string": [dict(pin(), dependencyName=7)],
}


@pytest.mark.parametrize("updates", PIN_REFUSED.values(), ids=PIN_REFUSED.keys())
def test_reusable_pins_input_accepts_nothing_else(updates, tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps(updates), psd_pins="true")
    assert r.rc == 0, r.out
    assert r.outputs.get("merge") == "false"
    assert r.pr_calls == []
    assert one_line(r.summary), r.summary


def test_a_pin_grouped_with_a_patch_dev_dep_merges_with_the_input_on(tmp_path):
    """Each update passes one of the two rules. Dependabot does not mix
    ecosystems in one PR, so this is the rule's edge, not a case seen."""
    r = run_step("decide", tmp_path, updates=json.dumps([pin(), dep()]), psd_pins="true")
    assert r.outputs.get("merge") == "true"


@pytest.mark.parametrize("updates", [[dep()], [dep("eslint"), dep("prettier")]], ids=["one", "group"])
def test_patch_dev_deps_still_merge_with_the_input_on(updates, tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps(updates), psd_pins="true")
    assert r.outputs.get("merge") == "true"
    assert len(r.pr_calls) == 1


def test_decision_merge_failure_fails_the_step(tmp_path):
    r = run_step("decide", tmp_path, updates=json.dumps([dep()]), gh={"FAIL_PR": "1"})
    assert r.rc != 0
    assert r.outputs.get("merge") != "true"


# --- an unapproved run turns off auto-merge an earlier run turned on -------

# A GITHUB_TOKEN-enabled auto-merge reports this login: psd401/psd-central-auth#236,
# REST auto_merge.enabled_by, read 2026-11-20.
ACTIONS_LOGIN = "github-actions[bot]"


def pull(enabled_by=ACTIONS_LOGIN):
    by = None if enabled_by is None else {"login": enabled_by, "type": "Bot" if "[bot]" in enabled_by else "User"}
    return json.dumps({"number": 7, "auto_merge": {"enabled_by": by, "merge_method": "squash"}})


def test_disable_turns_off_auto_merge_this_workflow_turned_on(tmp_path):
    r = run_step("disable", tmp_path, gh={"PULL": pull()})
    assert r.rc == 0, r.out
    assert len(r.pr_calls) == 1, r.calls
    args = r.pr_calls[0].split()
    assert args[:3] == ["pr", "merge", "--disable-auto"]
    assert PR_URL in args
    assert "::warning::" in r.out
    assert one_line(r.summary), r.summary


@pytest.mark.parametrize("login", ["octocat", "dependabot[bot]", "psd-automation[bot]", "github-actions", None],
                         ids=repr)
def test_disable_leaves_auto_merge_someone_else_turned_on(login, tmp_path):
    r = run_step("disable", tmp_path, gh={"PULL": pull(login)})
    assert r.rc == 0, r.out
    assert r.pr_calls == [], r.calls
    assert one_line(r.summary), r.summary
    assert "left on" in r.summary
    if login:
        assert login in r.summary


def test_disable_does_nothing_when_auto_merge_is_off(tmp_path):
    r = run_step("disable", tmp_path, gh={"PULL": json.dumps({"number": 7, "auto_merge": None})})
    assert r.rc == 0, r.out
    assert r.pr_calls == []
    assert r.summary == ""


@pytest.mark.parametrize("gh", [
    {"PULL": json.dumps({"auto_merge": None}), "FAIL_PULL": "1"},
    {"PULL": pull(), "FAIL_PR": "1"},
], ids=["read fails", "disable fails"])
def test_disable_failure_fails_the_step(gh, tmp_path):
    r = run_step("disable", tmp_path, gh=gh)
    assert r.rc != 0


# --- static shape -----------------------------------------------------------

def test_trigger_is_workflow_call_only():
    doc = workflow()
    assert True not in doc, 'quote "on": PyYAML reads a bare on: as True'
    assert set(doc["on"]) == {"workflow_call"}


def test_inputs_are_merge_method_and_the_pins_switch_which_is_off_by_default():
    call = workflow()["on"]["workflow_call"]
    assert set(call) == {"inputs"}, "no secrets or outputs"
    assert set(call["inputs"]) == {"merge_method", "psd_reusable_pins"}
    pins = call["inputs"]["psd_reusable_pins"]
    assert pins["type"] == "boolean"
    assert pins["default"] is False
    assert pins.get("required", False) is False
    m = call["inputs"]["merge_method"]
    assert m["type"] == "string"
    assert m["default"] == "squash"
    assert m.get("required", False) is False


def test_top_level_permissions_are_empty():
    assert workflow()["permissions"] == {}


def test_job_permissions_runner_and_timeout():
    j = job()
    assert j["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert j["runs-on"] == "ubuntu-latest"
    assert j["timeout-minutes"] == 5


def test_job_runs_only_for_dependabot_prs_from_this_repo():
    cond = job()["if"]
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in cond
    assert "github.event.pull_request.head.repo.full_name == github.repository" in cond
    assert "||" not in cond
    assert "github.actor" not in cond


def test_run_scripts_take_no_expressions_and_never_name_pull_request_target():
    scripts = run_scripts()
    assert scripts
    for script in scripts:
        assert "${{" not in script, script
        assert "pull_request_target" not in script, script


def test_every_env_value_is_a_modeled_expression():
    for s in job()["steps"]:
        for var, expr in (s.get("env") or {}).items():
            assert expr in EXPR.values(), f"{s.get('id')}: {var}={expr}"
            if var == "GH_TOKEN":
                assert expr == EXPR["token"]


def test_every_gh_api_step_sets_pipefail():
    for script in run_scripts():
        if "gh api" in script:
            assert "set -o pipefail" in script, script


def test_fetch_metadata_is_pinned_and_verifies_commits():
    s = step("metadata")
    assert s["uses"] == FETCH_METADATA
    w = s.get("with") or {}
    assert w.get("skip-commit-verification") is False
    assert "skip-verification" not in w


def test_every_uses_is_sha_pinned_with_one_version_comment():
    lines = [ln.strip() for ln in WORKFLOW.read_text().splitlines()
             if re.match(r"\s*(?:-\s*)?uses:", ln)]
    assert lines
    for ln in lines:
        assert re.fullmatch(r"(?:-\s*)?uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(?:\.\d+)*", ln), ln
        assert ln.count("#") == 1, ln


@pytest.mark.parametrize("step_id", ["metadata", "decide"])
def test_metadata_and_decision_run_only_after_both_gates(step_id):
    cond = step(step_id)["if"]
    assert "steps.gate.outputs.enforced == 'true'" in cond
    assert "steps.provenance.outputs.dependabot == 'true'" in cond
    assert "||" not in cond


def test_only_the_decision_step_turns_on_auto_merge():
    merging = [s.get("id") for s in job()["steps"] if "--auto" in s.get("run", "").replace("--disable-auto", "")]
    assert merging == ["decide"]


def test_disable_runs_whenever_the_decision_did_not_merge():
    s = step("disable")
    assert job()["steps"][-1] is s
    cond = s["if"]
    assert "!cancelled()" in cond
    assert "steps.decide.outputs.merge != 'true'" in cond


def header():
    lines = []
    for ln in WORKFLOW.read_text().splitlines():
        if not ln.startswith("#"):
            break
        lines.append(ln)
    return lines


def test_header_explains_the_trigger():
    text = " ".join(" ".join(header()).split())
    assert "pull_request_target" in text
    assert "read-only" in text


def test_header_caller_snippet_is_a_valid_caller():
    lines = header()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("# Caller"))
    snippet = "\n".join(ln[4:] for ln in lines[start + 1:] if ln.startswith("#   "))
    caller = yaml.load(snippet, Loader=yaml.BaseLoader)
    assert caller["on"] == "pull_request"
    assert caller["permissions"] == {}
    (call,) = caller["jobs"].values()
    assert call["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in call["if"]
    assert call["uses"].startswith("PSD401/.github/.github/workflows/reusable-dependabot-auto-merge.yml@")
    assert call["with"]["merge_method"] in METHODS
    assert set(call["with"]) <= set(workflow()["on"]["workflow_call"]["inputs"])
