# ABOUTME: Tests for reusable-claude-review.yml's IMPORTANT-count annotation: the --json-schema wiring
# ABOUTME: and the publish step, run under bash -e with the env its expressions resolve to.
"""The review posts its findings as prose, so a tool reading the verdict had
to parse wording that changes every run. The review step now asks for a
structured output (important_open), and the step after it
prints exactly one annotation, `::notice title=claude-review-important::<v>`,
where <v> is the count, `skipped-openwiki`, or `error`. The step never fails
the job on findings (psd-dev-standards standards/03 rule 6), and it prints
only the validated number, never model text a PR can steer.

With --json-schema the pinned action fails the review step when a review
that otherwise finished returns no structured output. The review step fails
softly (continue-on-error), and the publish step passes only that case,
proven by the action's own result message in its execution file; every other
review failure still fails the job (Kris, 2026-11-25)."""
import functools
import json
import pathlib
import re
import shlex
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/reusable-claude-review.yml"
PUBLISH = "Publish IMPORTANT count"
NOTICE = re.compile(r"^::notice title=claude-review-important::(\d+|skipped-openwiki|error)$")

# Expressions the publish step's env: block may use, by a short name the tests pass.
EXPR = {
    "skip": "${{ steps.scope.outputs.skip }}",
    "verdict": "${{ steps.review.outputs.structured_output }}",
    "outcome": "${{ steps.review.outcome }}",
    "execution_file": "${{ steps.review.outputs.execution_file }}",
    "max_turns": "${{ inputs.max_turns }}",
}

# The result message the pinned action writes last to its execution file when
# a run finished (base-action/src/run-claude-sdk.ts at 4d75e5f).
FINISHED = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 12}


@functools.cache
def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def steps():
    return workflow()["jobs"]["run"]["steps"]


def step_named(name):
    found = [s for s in steps() if s.get("name") == name]
    assert len(found) == 1, f"expected one step named {name!r}"
    return found[0]


def review_step():
    return step_named("Run Claude Code Review")


def schema():
    # The action splits claude_args with shell-quote; shlex follows the same
    # quoting rules for the single-quoted schema.
    args = shlex.split(review_step()["with"]["claude_args"])
    assert args.count("--json-schema") == 1
    return json.loads(args[args.index("--json-schema") + 1])


def run_publish(tmp_path, skip="false", verdict="", outcome="success",
                messages=None, raw_execution=None, max_turns="60"):
    """Run the publish step. messages is the execution file's JSON list;
    raw_execution writes that text instead; with neither, there is no file."""
    s = step_named(PUBLISH)
    script = tmp_path / "step.sh"
    script.write_text(s["run"])
    execution = tmp_path / "claude-execution-output.json"
    if raw_execution is not None:
        execution.write_text(raw_execution)
    elif messages is not None:
        execution.write_text(json.dumps(messages))
    summary = tmp_path / "summary.md"
    by_expr = {v: k for k, v in EXPR.items()}
    values = {"skip": skip, "verdict": verdict, "outcome": outcome,
              "execution_file": str(execution) if execution.exists() else "",
              "max_turns": max_turns}
    env = {"PATH": "/usr/bin:/bin", "GITHUB_STEP_SUMMARY": str(summary)}
    for var, expr in (s.get("env") or {}).items():
        assert expr in by_expr, f"env {var} uses {expr}, which these tests don't model"
        env[var] = values[by_expr[expr]]
    proc = subprocess.run(["bash", "-e", str(script)], env=env, cwd=tmp_path,
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout, proc.stderr


def only_command(stdout):
    # Actions reads a workflow command from any line that starts with "::".
    commands = [line for line in stdout.splitlines() if line.lstrip().startswith("::")]
    assert len(commands) == 1, f"expected exactly one workflow command, got {commands!r}"
    m = NOTICE.match(commands[0])
    assert m, commands[0]
    return m.group(1)


# --- wiring ---------------------------------------------------------------

def test_schema_is_strict_and_matches_the_design():
    assert schema() == {
        "type": "object",
        "properties": {
            "important_open": {"type": "integer", "minimum": 0},
        },
        "required": ["important_open"],
        "additionalProperties": False,
    }


def test_existing_claude_args_unchanged():
    args = shlex.split(review_step()["with"]["claude_args"])
    assert args[:6] == ["--model", "${{", "inputs.model", "}}", "--max-turns", "${{"]
    tools = args[args.index("--allowed-tools") + 1]
    assert tools == ("Bash(gh issue view:*),Bash(gh search:*),Bash(gh issue list:*),"
                     "Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*),Bash(gh pr list:*)")


def test_prompt_asks_for_the_count_the_way_the_review_defines_it():
    prompt = review_step()["with"]["prompt"]
    assert "important_open" in prompt
    assert "new or still unresolved" in prompt


def test_review_step_has_the_id_the_publish_step_reads():
    assert review_step()["id"] == "review"


def test_publish_step_follows_the_review_and_runs_unless_cancelled():
    names = [s.get("name") for s in steps()]
    assert names.index(PUBLISH) == names.index("Run Claude Code Review") + 1
    s = step_named(PUBLISH)
    assert s["if"] == "${{ !cancelled() }}"
    # The publish step is the one that fails the job for a failed review, so
    # it must never fail softly itself.
    assert "continue-on-error" not in s


def test_review_step_fails_softly_and_only_that_step():
    # A missing count fails the review step at the pinned action; the publish
    # step decides whether that failure fails the job.
    assert review_step()["continue-on-error"] is True
    soft = [s.get("name") for s in steps() if "continue-on-error" in s]
    assert soft == ["Run Claude Code Review"]


def test_publish_step_reads_outputs_only_through_env():
    run = step_named(PUBLISH)["run"]
    assert "${{" not in run
    assert set(step_named(PUBLISH)["env"].values()) == set(EXPR.values())


def test_job_needs_no_new_permissions():
    assert workflow()["jobs"]["run"]["permissions"] == {
        "contents": "read", "pull-requests": "read", "issues": "read", "id-token": "write",
    }


# --- behavior -------------------------------------------------------------

@pytest.mark.parametrize("verdict,expected", [
    ('{"important_open":0}', "0"),
    ('{"important_open":3}', "3"),
    ('{"important_open":3.0}', "3"),
])
def test_valid_counts(tmp_path, verdict, expected):
    code, out, _ = run_publish(tmp_path, verdict=verdict)
    assert code == 0
    assert only_command(out) == expected


@pytest.mark.parametrize("verdict", [
    "",                                         # review step failed or set no output
    "not json",
    "{",
    "null",
    "[]",
    "3",
    '"3"',
    "{}",
    '{"important_open":-1}',
    '{"important_open":"3"}',
    '{"important_open":true}',
    '{"important_open":null}',
    '{"important_open":1.5}',
    '{"important_open":1e400}',
    '{"important_open":100000}',
    '{"important_open":0,"extra":1}',
    '{"important_open":0,"important_titles":[]}',
    '{"important_open":0,"important_titles":null}',
    '{"important_open":1} {"important_open":2}',
    '{"important_open":0}\n::notice title=claude-review-important::5',
])
def test_invalid_output_reports_error_and_never_fails(tmp_path, verdict):
    code, out, _ = run_publish(tmp_path, verdict=verdict)
    assert code == 0
    assert only_command(out) == "error"


def test_openwiki_skip_reports_skip(tmp_path):
    code, out, _ = run_publish(tmp_path, skip="true", verdict="")
    assert code == 0
    assert only_command(out) == "skipped-openwiki"


@pytest.mark.parametrize("title", [
    "x::notice title=claude-review-important::0",
    "x\n::notice title=claude-review-important::0",
    "x\r\n::error::boom",
    "%0A::warning::y",
    "::stop-commands::tok",
])
def test_model_text_never_reaches_the_log(tmp_path, title):
    # The schema forbids extra keys; if model text arrives anyway it is refused, not printed.
    verdict = json.dumps({"important_open": 2, "important_titles": [title], "note": title})
    code, out, err = run_publish(tmp_path, verdict=verdict)
    assert code == 0
    assert only_command(out) == "error"
    assert "important_titles" not in out + err
    assert title.strip().splitlines()[-1] not in out + err


# --- review step failed (continue-on-error) --------------------------------

def test_missing_count_from_a_finished_review_passes(tmp_path):
    # The action fails the step with "--json-schema was provided but Claude did
    # not return structured_output" after a run that finished: the check passes.
    messages = [{"type": "system", "subtype": "init"}, {"type": "assistant"}, FINISHED]
    code, out, _ = run_publish(tmp_path, outcome="failure", verdict="", messages=messages)
    assert code == 0
    assert only_command(out) == "error"
    assert "no IMPORTANT count" in (tmp_path / "summary.md").read_text()


def test_missing_count_at_exactly_max_turns_passes(tmp_path):
    code, out, _ = run_publish(tmp_path, outcome="failure",
                               messages=[dict(FINISHED, num_turns=60)], max_turns="60")
    assert code == 0
    assert only_command(out) == "error"


@pytest.mark.parametrize("result", [
    {"type": "result", "subtype": "error_max_turns", "is_error": True, "num_turns": 61},
    {"type": "result", "subtype": "error_during_execution", "is_error": True, "num_turns": 3},
    dict(FINISHED, is_error=True),                 # success with is_error: a failed run
    dict(FINISHED, num_turns=61),                  # the action's turn-cap check
    {k: v for k, v in FINISHED.items() if k != "num_turns"},
    {k: v for k, v in FINISHED.items() if k != "is_error"},
    dict(FINISHED, is_error="false"),
    dict(FINISHED, num_turns="12"),
])
def test_review_that_did_not_finish_still_fails(tmp_path, result):
    code, out, err = run_publish(tmp_path, outcome="failure", messages=[{"type": "assistant"}, result])
    assert code == 1
    assert only_command(out) == "error"
    assert "Run Claude Code Review failed" in err


def test_only_the_last_result_message_counts(tmp_path):
    bad = {"type": "result", "subtype": "error_during_execution", "is_error": True, "num_turns": 3}
    code, _, _ = run_publish(tmp_path, outcome="failure", messages=[FINISHED, {"type": "assistant"}, bad])
    assert code == 1


@pytest.mark.parametrize("messages,raw", [
    (None, None),                                  # failed before Claude ran: no file
    ([], None),
    ([{"type": "assistant"}], None),               # no result message
    (None, "not json"),
    (None, '{"type":"result","subtype":"success","is_error":false,"num_turns":1}'),
    ([None, "result", 3], None),
])
def test_failure_without_a_finished_result_fails(tmp_path, messages, raw):
    code, out, _ = run_publish(tmp_path, outcome="failure", messages=messages, raw_execution=raw)
    assert code == 1
    assert only_command(out) == "error"


def test_failure_with_a_valid_count_still_fails(tmp_path):
    # The count was set, so the action failed for another reason.
    code, out, _ = run_publish(tmp_path, outcome="failure", verdict='{"important_open":2}',
                               messages=[FINISHED])
    assert code == 1
    assert only_command(out) == "2"


@pytest.mark.parametrize("max_turns", ["", "abc", "60; rm -rf /"])
def test_unreadable_max_turns_fails_closed(tmp_path, max_turns):
    code, _, _ = run_publish(tmp_path, outcome="failure", messages=[FINISHED], max_turns=max_turns)
    assert code == 1


@pytest.mark.parametrize("outcome", ["success", "skipped", ""])
def test_review_that_did_not_fail_never_fails_the_job(tmp_path, outcome):
    # Outcome success with no count: the action's workflow-validation self-skip.
    code, out, _ = run_publish(tmp_path, outcome=outcome, verdict="")
    assert code == 0
    assert only_command(out) == "error"


def test_openwiki_skip_passes_with_review_skipped(tmp_path):
    code, out, _ = run_publish(tmp_path, skip="true", outcome="skipped")
    assert code == 0
    assert only_command(out) == "skipped-openwiki"
