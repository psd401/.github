# ABOUTME: Tests for schemas/iac/environment-file.schema.json's student-pii addition:
# ABOUTME: cloud.aws.student_pii, the account-baseline and account-rego inputs.
import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "iac" / "environment-file.schema.json").read_text())
FULL = yaml.safe_load((HERE / "fixtures" / "env-student-pii.yml").read_text())
spec = importlib.util.spec_from_file_location("check_custom_identifiers",
                                              HERE / "check_custom_identifiers.py")
identifiers_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identifiers_mod)


def errors(data):
    """(absolute path, failing keyword) for every schema error, the same validator
    reusable-env-file-check.yml runs (no format checker)."""
    return {(tuple(e.absolute_path), e.validator)
            for e in Draft202012Validator(SCHEMA).iter_errors(data)}


@pytest.mark.parametrize("env_file", [
    HERE / "fixtures" / "env-student-pii.yml",
    HERE / "fixtures" / "district.example.yml",
    ROOT / "schemas" / "iac" / "example.env.yml",
])
def test_valid_files_pass(env_file):
    assert errors(yaml.safe_load(env_file.read_text())) == set()


def student_pii_without_regions(env):
    del env["cloud"]["aws"]["student_pii"]["regions"]
    return ("cloud", "aws", "student_pii"), "required"


def unknown_guardrail_mode(env):
    env["cloud"]["aws"]["student_pii"]["guardrail_mode"] = "scp"
    return ("cloud", "aws", "student_pii", "guardrail_mode"), "enum"


def unknown_student_pii_key(env):
    env["cloud"]["aws"]["student_pii"]["applications"] = []
    return ("cloud", "aws", "student_pii"), "additionalProperties"


def privacy_block_is_not_a_key(env):
    env["privacy"] = {"records_procedure": {}}
    return (), "additionalProperties"


def empty_managed_identifiers(env):
    env["cloud"]["aws"]["student_pii"]["managed_identifiers"] = []
    return ("cloud", "aws", "student_pii", "managed_identifiers"), "minItems"


def student_pii_without_permission_set(env):
    del env["cloud"]["aws"]["student_pii"]["breakglass_permission_set_name"]
    return ("cloud", "aws", "student_pii"), "required"


def wildcard_permission_set(env):
    env["cloud"]["aws"]["student_pii"]["breakglass_permission_set_name"] = "StudentPii*"
    return ("cloud", "aws", "student_pii", "breakglass_permission_set_name"), "pattern"


def long_permission_set(env):
    env["cloud"]["aws"]["student_pii"]["breakglass_permission_set_name"] = "p" * 33
    return ("cloud", "aws", "student_pii", "breakglass_permission_set_name"), "pattern"


@pytest.mark.parametrize("mutate", [
    student_pii_without_regions, unknown_guardrail_mode, unknown_student_pii_key,
    privacy_block_is_not_a_key, empty_managed_identifiers,
    student_pii_without_permission_set, wildcard_permission_set, long_permission_set,
])
def test_malformed_record_fails_at_the_named_key(mutate):
    env = copy.deepcopy(FULL)
    expected = mutate(env)
    assert expected in errors(env)


def regex_errors(regex):
    """Failing keywords at the first custom identifier's regex."""
    env = copy.deepcopy(FULL)
    env["cloud"]["aws"]["student_pii"]["custom_identifiers"][0]["regex"] = regex
    return {kw for where, kw in errors(env)
            if where == ("cloud", "aws", "student_pii", "custom_identifiers", 0, "regex")}


def test_custom_identifier_regex_takes_exactly_the_cloudwatch_set():
    """The character set check_custom_identifiers.py enforces, one character at a time."""
    candidates = {chr(c) for c in range(0x20, 0x7f)} | {"\t", "\n", "é"}
    assert {c for c in candidates if not regex_errors(c)} == identifiers_mod.REGEX_CHARS


def test_custom_identifier_regex_with_a_trailing_newline_fails():
    """A YAML block scalar (regex: |) ends the value in a newline, which a $ anchor lets through."""
    assert regex_errors("ESD[0-9]{7}\n") == {"pattern"}
