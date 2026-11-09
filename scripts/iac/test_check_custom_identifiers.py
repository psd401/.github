# ABOUTME: Tests for check_custom_identifiers.py: each cloud.aws.student_pii custom data
# ABOUTME: identifier meets the CloudWatch Logs limits and its own test strings under Python re.
"""Limits: name at most 128 characters from a-zA-Z0-9_-, regex at most 200
characters from alphanumerics, _ # = @ / ; , - space and ^ $ ? [ ] { } | \\ * + .
(CloudWatch Logs User Guide, Custom data identifiers, read 2026-10-23)."""
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).parent
SCRIPT = HERE / "check_custom_identifiers.py"
PII_ENV = HERE / "fixtures" / "env-student-pii.yml"
NO_PII_ENV = HERE / "fixtures" / "district.example.yml"
LABEL = "approximation of the CloudWatch engine"


def run(env_file):
    return subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env_file)],
                          capture_output=True, text=True)


def with_identifier(tmp_path, **fields):
    """The student-pii fixture with its one custom identifier's fields replaced."""
    env = yaml.safe_load(PII_ENV.read_text())
    env["cloud"]["aws"]["student_pii"]["custom_identifiers"][0].update(fields)
    out = tmp_path / "env.yml"
    out.write_text(yaml.safe_dump(env))
    return out


def test_passing_identifier_prints_a_labelled_table():
    r = run(PII_ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    assert LABEL in r.stdout
    for shown in ("StudentId", "S1234567", "S12345"):
        assert shown in r.stdout


def test_absent_block_passes():
    r = run(NO_PII_ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no student_pii block" in r.stdout


@pytest.mark.parametrize("name", ["S" * 129, "Student.Id", "Student Id"])
def test_name_outside_cloudwatch_limits_fails(tmp_path, name):
    r = run(with_identifier(tmp_path, name=name))
    assert r.returncode == 1
    assert "| name |  | fail |" in r.stdout


def test_regex_over_200_characters_fails(tmp_path):
    regex = "S[0-9]{7}|" + "z" * 191
    r = run(with_identifier(tmp_path, regex=regex))
    assert r.returncode == 1
    assert "201 characters, limit 200" in r.stdout


@pytest.mark.parametrize("regex", ["(S[0-9]{7})", "S[0-9]{7}:?", 'S[0-9]{7}"?', "S[0-9]{7}%?"])
def test_regex_character_outside_cloudwatch_set_fails(tmp_path, regex):
    r = run(with_identifier(tmp_path, regex=regex))
    assert r.returncode == 1
    assert "outside the CloudWatch character set" in r.stdout


def test_match_string_the_regex_misses_fails(tmp_path):
    r = run(with_identifier(tmp_path, test_matches=["S1234567", "S123"]))
    assert r.returncode == 1
    assert "| must match | 'S123' | fail |" in r.stdout


def test_non_match_string_the_regex_matches_fails(tmp_path):
    r = run(with_identifier(tmp_path, test_non_matches=["S12345", "S7654321"]))
    assert r.returncode == 1
    assert "| must not match | 'S7654321' | fail |" in r.stdout


def test_regex_python_cannot_compile_fails_without_a_traceback(tmp_path):
    r = run(with_identifier(tmp_path, regex="S[0-9"))
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "does not compile" in r.stdout


def env_strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from env_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from env_strings(value)
    elif isinstance(node, str):
        yield node


def test_prints_no_env_value_but_identifier_names_and_test_strings(tmp_path):
    leaky = '"student_id": ?(S[0-9'
    failing = with_identifier(tmp_path, regex=leaky)
    broken = tmp_path / "broken.yml"
    broken.write_text("cloud:\n  aws:\n    student_pii: [zzsecretzz, {\n")
    env = yaml.safe_load(PII_ENV.read_text())
    identifier = env["cloud"]["aws"]["student_pii"]["custom_identifiers"][0]
    allowed = {identifier["name"], *identifier["test_matches"], *identifier["test_non_matches"]}
    secret = {s for s in env_strings(env) if len(s) >= 8} - allowed
    for env_file, extra in ((PII_ENV, set()), (failing, {leaky}), (broken, {"zzsecretzz"})):
        r = run(env_file)
        output = (r.stdout + r.stderr).replace(str(env_file), "")
        assert "Traceback" not in output
        for value in secret | extra:
            assert value not in output, f"{env_file.name} printed {value!r}"
