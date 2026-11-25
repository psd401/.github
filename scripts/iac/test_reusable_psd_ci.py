# ABOUTME: Tests for reusable-psd-ci.yml's upstream-results and gate inputs. Each run step executes
# ABOUTME: under bash -e with the env its expressions resolve to; the rest are checks on the wiring.
"""psd-dev-standards issue #80 (CIO decision 2026-10-13): a repo whose gates
can't run in the reusable runs them as jobs in its own caller, passes
join(needs.*.result, ' ') as upstream-results, and may set gate: off. The
reusable still produces psd-ci / psd-ci, fails unless every upstream result
is success, and always runs the runtime-standard step. gate: off is valid
only with upstream results. Defaults (upstream-results "", gate auto) must
leave existing callers unchanged.

The behavior tests pull a step's run: script out of the workflow and run it
the way Actions does (bash -e). env: values are resolved from the
expressions the workflow wires in, so a test fails if that wiring changes."""
import functools
import pathlib
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/reusable-psd-ci.yml"
GATE_OFF = "inputs.gate != 'off'"

# Expressions the two new steps' env: blocks may use, by a short name the tests pass.
EXPR = {
    "gate": "${{ inputs.gate }}",
    "upstream": "${{ inputs.upstream-results }}",
}


@functools.cache
def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def inputs():
    # PyYAML reads the `on` key as True (YAML 1.1).
    return workflow()[True]["workflow_call"]["inputs"]


def steps():
    return workflow()["jobs"]["run"]["steps"]


def step_named(name):
    found = [s for s in steps() if s.get("name") == name]
    assert len(found) == 1, f"expected one step named {name!r}"
    return found[0]


def index_of(pred):
    found = [i for i, s in enumerate(steps()) if pred(s)]
    assert len(found) == 1
    return found[0]


def run_step(name, tmp_path, **values):
    s = step_named(name)
    script = tmp_path / "step.sh"
    script.write_text(s["run"])
    by_expr = {v: k for k, v in EXPR.items()}
    env = {"PATH": "/usr/bin:/bin"}
    defaults = {k: v["default"] for k, v in (("gate", inputs()["gate"]), ("upstream", inputs()["upstream-results"]))}
    for var, expr in (s.get("env") or {}).items():
        assert expr in by_expr, f"{name}: env {var} uses {expr}, which these tests don't model"
        key = by_expr[expr]
        env[var] = values.get(key, defaults[key])
    # cwd holds a file named "success" so an unquoted glob in the script would show.
    (tmp_path / "success").write_text("")
    proc = subprocess.run(["bash", "-e", str(script)], env=env, cwd=tmp_path,
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout + proc.stderr


# --- inputs ---------------------------------------------------------------

def test_new_inputs_are_optional_strings_with_todays_defaults():
    ins = inputs()
    assert ins["upstream-results"]["type"] == "string"
    assert ins["upstream-results"]["default"] == ""
    assert ins["gate"]["type"] == "string"
    assert ins["gate"]["default"] == "auto"
    assert not ins["upstream-results"].get("required")
    assert not ins["gate"].get("required")


def test_job_and_check_name_unchanged():
    # The caller job psd-ci plus this job's name gives the required `psd-ci / psd-ci`.
    assert list(workflow()["jobs"]) == ["run", "secret-scan"]
    assert workflow()["jobs"]["run"]["name"] == "psd-ci"


def test_new_steps_read_inputs_only_through_env():
    for name in ("Check gate inputs", "Upstream gate jobs"):
        assert "${{" not in step_named(name)["run"], name


# --- Check gate inputs ----------------------------------------------------

@pytest.mark.parametrize("gate,upstream", [
    ("auto", ""),
    ("auto", "success failure"),
    ("off", "success"),
    ("off", "success success skipped"),
])
def test_gate_inputs_accepted(gate, upstream, tmp_path):
    rc, out = run_step("Check gate inputs", tmp_path, gate=gate, upstream=upstream)
    assert rc == 0, out


def test_gate_inputs_defaults_pass(tmp_path):
    rc, out = run_step("Check gate inputs", tmp_path)
    assert rc == 0, out


@pytest.mark.parametrize("upstream", ["", " ", "\t \n"])
def test_gate_off_without_upstream_fails(upstream, tmp_path):
    rc, out = run_step("Check gate inputs", tmp_path, gate="off", upstream=upstream)
    assert rc == 1
    assert "::error::gate: off needs upstream-results" in out


@pytest.mark.parametrize("gate", ["", "Off", "false", "on", "auto "])
def test_unknown_gate_value_fails(gate, tmp_path):
    rc, out = run_step("Check gate inputs", tmp_path, gate=gate, upstream="success")
    assert rc == 1
    assert "::error::gate must be auto or off" in out


# --- Upstream gate jobs ---------------------------------------------------

@pytest.mark.parametrize("upstream", ["", "   ", "success", "success success", " success\tsuccess "])
def test_upstream_passes(upstream, tmp_path):
    rc, out = run_step("Upstream gate jobs", tmp_path, upstream=upstream)
    assert rc == 0, out


def test_upstream_default_is_a_no_op(tmp_path):
    rc, out = run_step("Upstream gate jobs", tmp_path)
    assert rc == 0, out
    assert "upstream jobs: none" in out


@pytest.mark.parametrize("upstream,bad", [
    ("failure", "failure"),
    ("success failure", "failure"),
    ("success cancelled", "cancelled"),
    ("skipped success", "skipped"),
    ("Success", "Success"),
    ("success *", "*"),
])
def test_upstream_fails_unless_every_word_is_success(upstream, bad, tmp_path):
    rc, out = run_step("Upstream gate jobs", tmp_path, upstream=upstream)
    assert rc == 1, out
    assert f"::error::An upstream gate job did not succeed ({bad})." in out


def test_upstream_reports_every_failed_word(tmp_path):
    rc, out = run_step("Upstream gate jobs", tmp_path, upstream="failure success skipped")
    assert rc == 1
    assert "(failure)" in out and "(skipped)" in out


# --- step wiring ----------------------------------------------------------

def test_inputs_checked_before_anything_but_checkout():
    first_run = index_of(lambda s: "run" in s and s.get("name") == "Check gate inputs")
    assert all("uses" in s and s["uses"].startswith("actions/checkout@") for s in steps()[:first_run])


def test_runtime_standard_and_upstream_rollup_run_whatever_the_gate():
    for name in ("Check gate inputs", "Runtime standard (bun for JS/TS, uv for Python — standards/02)",
                 "Upstream gate jobs"):
        assert "if" not in step_named(name), name


def test_upstream_rollup_runs_after_runtime_standard_and_before_install():
    runtime = index_of(lambda s: (s.get("name") or "").startswith("Runtime standard"))
    rollup = index_of(lambda s: s.get("name") == "Upstream gate jobs")
    install = index_of(lambda s: s.get("name") == "Install")
    assert runtime < rollup < install


# Exact conditions, not substrings: an `||`, or a status function such as
# always(), would let a step run under gate: off or after a failed upstream
# rollup (a step `if:` with no status function implies success()).
GATED_IFS = {
    "actions/setup-node": GATE_OFF + """ && contains(fromJSON('["npm","npm-nolock","pnpm","yarn"]'), steps.pm.outputs.pm)""",
    "oven-sh/setup-bun": GATE_OFF + " && steps.pm.outputs.pm == 'bun'",
    "astral-sh/setup-uv": GATE_OFF + " && steps.pm.outputs.pm == 'uv'",
    "Install": GATE_OFF,
    "Run gate": GATE_OFF,
}


def test_gate_off_skips_setup_install_and_gate():
    seen = {}
    for s in steps():
        key = s.get("name") if s.get("name") in GATED_IFS else (s.get("uses") or "").split("@")[0]
        if key in GATED_IFS:
            seen[key] = s.get("if")
    assert seen == GATED_IFS


def test_only_those_steps_depend_on_gate():
    for s in steps():
        if (s.get("name") in ("Install", "Run gate")
                or (s.get("uses") or "").split("@")[0] in ("actions/setup-node", "oven-sh/setup-bun", "astral-sh/setup-uv")):
            continue
        assert "inputs.gate" not in str(s.get("if", "")), s.get("name") or s.get("uses")


def test_secret_scan_job_does_not_depend_on_gate():
    job = workflow()["jobs"]["secret-scan"]
    assert job["if"] == "inputs.secret-scan-mode != 'off'"


# --- Run gate: an empty test-command ---------------------------------------
# psd-dev-standards standards/05-testing.md gate 3 (CIO decision 2026-11-25):
# test-command "" used to skip tests without failing.

RUN_GATE_ENV = {
    "PM": "${{ steps.pm.outputs.pm }}",
    "LINT_CMD": "${{ inputs.lint-command }}",
    "TYPECHECK_CMD": "${{ inputs.typecheck-command }}",
    "BUILD_CMD": "${{ inputs.build-command }}",
    "TEST_CMD": "${{ inputs.test-command }}",
    "ALLOW_NO_TESTS": "${{ inputs.allow-no-tests }}",
    "UPSTREAM_RESULTS": "${{ inputs.upstream-results }}",
}


def run_gate(tmp_path, test_cmd, allow="false", upstream=""):
    s = step_named("Run gate")
    assert s["env"] == RUN_GATE_ENV
    script = tmp_path / "gate.sh"
    script.write_text(s["run"])
    # lint, typecheck and build are "" so only the test branch runs.
    env = {"PATH": "/usr/bin:/bin", "PM": "none", "LINT_CMD": "", "TYPECHECK_CMD": "", "BUILD_CMD": "",
           "TEST_CMD": test_cmd, "ALLOW_NO_TESTS": allow, "UPSTREAM_RESULTS": upstream}
    proc = subprocess.run(["bash", "-e", str(script)], env=env, cwd=tmp_path,
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout + proc.stderr


def test_empty_test_command_fails(tmp_path):
    rc, out = run_gate(tmp_path, "")
    assert rc == 1, out
    assert "::error::test-command is empty" in out


@pytest.mark.parametrize("upstream", [" ", "\t \n"])
def test_empty_test_command_fails_with_blank_upstream(upstream, tmp_path):
    rc, out = run_gate(tmp_path, "", upstream=upstream)
    assert rc == 1, out


def test_empty_test_command_allowed_with_allow_no_tests(tmp_path):
    rc, out = run_gate(tmp_path, "", allow="true")
    assert rc == 0, out
    assert "::warning::test-command is empty" in out


def test_empty_test_command_allowed_with_upstream_jobs(tmp_path):
    rc, out = run_gate(tmp_path, "", upstream="success success")
    assert rc == 0, out
    assert "upstream gate jobs run the tests" in out


def test_custom_test_command_still_runs_and_its_failure_fails_the_gate(tmp_path):
    rc, out = run_gate(tmp_path, "echo ran-tests")
    assert rc == 0 and "ran-tests" in out, out
    rc, out = run_gate(tmp_path, "false")
    assert rc != 0, out

