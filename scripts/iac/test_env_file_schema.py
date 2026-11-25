# ABOUTME: Tests for schemas/iac/environment-file.schema.json's conftest-data additions:
# ABOUTME: cloud.aws.student_pii (account baseline and account rego) and cloud.aws.ses (SES From list).
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
    HERE / "fixtures" / "district.unfilled.yml",
    ROOT / "schemas" / "iac" / "example.env.yml",
])
def test_valid_files_pass(env_file):
    assert errors(yaml.safe_load(env_file.read_text())) == set()


UNFILLED = yaml.safe_load((HERE / "fixtures" / "district.unfilled.yml").read_text())

# Keys with no real value anywhere yet: optional in the schema, never a placeholder
# (PSD401/.github env-schema-optional-unfilled). Each path is absent from
# district.unfilled.yml, and each is type-checked when present.
OPTIONAL_UNTIL_FILLED = {
    ("network", "vlans", "management", "allowed_data_classifications"): ["internal"],
    ("network", "vlans", "workload", "allowed_data_classifications"): ["internal"],
    ("network", "vlans", "storage", "allowed_data_classifications"): ["internal"],
    ("patch_window",): "Sun 02:00-04:00",
    ("cloud", "aws", "account_alias", "sandbox"): "sandbox-alias",
    ("cloud", "aws", "alerts_topic_name"): "example-alerts",
    ("cloud", "aws", "bedrock_default_model_id"): "anthropic.claude-x",
    ("cloud", "gcp", "project_id"): {"prod": "gcp-prod", "nonprod": "gcp-nonprod"},
    ("operations", "change_request_system"): "example-itsm",
    ("contacts",): {"iac_owner_role": "infrastructure engineer"},
}


def get(env, path):
    for p in path:
        env = env.get(p) if isinstance(env, dict) else None
    return env


def put(env, path, value):
    for p in path[:-1]:
        env = env.setdefault(p, {})
    env[path[-1]] = value


@pytest.mark.parametrize("path", sorted(OPTIONAL_UNTIL_FILLED))
def test_unfilled_fixture_leaves_out_each_optional_key(path):
    assert get(UNFILLED, path) is None


@pytest.mark.parametrize("path, value", sorted(OPTIONAL_UNTIL_FILLED.items()))
def test_optional_key_with_a_real_shaped_value_passes(path, value):
    env = copy.deepcopy(UNFILLED)
    put(env, path, value)
    assert errors(env) == set()


VLAN_CLASSES = ("network", "vlans", "workload", "allowed_data_classifications")


@pytest.mark.parametrize("path, bad, where, keyword", [
    (VLAN_CLASSES, "internal", VLAN_CLASSES, "type"),
    (VLAN_CLASSES, ["secret"], VLAN_CLASSES + (0,), "enum"),
    (VLAN_CLASSES, [], VLAN_CLASSES, "minItems"),
    (("patch_window",), 4, None, "type"),
    (("cloud", "aws", "account_alias", "sandbox"), ["sandbox-alias"], None, "type"),
    (("cloud", "aws", "alerts_topic_name"), {"name": "x"}, None, "type"),
    (("cloud", "aws", "bedrock_default_model_id"), 7, None, "type"),
    (("cloud", "gcp", "project_id"), "gcp-prod", None, "type"),
    (("cloud", "gcp", "project_id", "prod"), 12, None, "type"),
    (("operations", "change_request_system"), True, None, "type"),
    (("contacts", "iac_owner_role"), ["engineer"], None, "type"),
])
def test_optional_key_present_but_wrongly_typed_still_fails(path, bad, where, keyword):
    env = copy.deepcopy(UNFILLED)
    put(env, path, bad)
    assert (where or path, keyword) in errors(env)


@pytest.mark.parametrize("path, extra", [
    (("contacts",), "owner_name"),
    (("cloud", "gcp", "project_id"), "sandbox"),
    (("network", "vlans", "storage"), "classifications"),
])
def test_optional_blocks_still_reject_unknown_keys(path, extra):
    env = copy.deepcopy(UNFILLED)
    put(env, path, dict(get(env, path) or {}, **{extra: "x"}))
    assert (path, "additionalProperties") in errors(env)


@pytest.mark.parametrize("path", [
    ("district_id",), ("network",), ("timezone",), ("monitoring",), ("virtualization",),
    ("cloud",), ("oidc",), ("operations",),
    ("network", "vlans", "workload", "id"), ("network", "vlans", "workload", "subnet"),
    ("cloud", "aws", "state_bucket_prefix"), ("cloud", "aws", "account_alias", "prod"),
    ("cloud", "aws", "account_alias", "nonprod"), ("cloud", "aws", "region_default"),
    ("cloud", "aws", "region_ai"), ("cloud", "gcp", "state_backend"),
])
def test_keys_with_real_values_stay_required(path):
    env = copy.deepcopy(UNFILLED)
    del (get(env, path[:-1]) if len(path) > 1 else env)[path[-1]]
    assert (path[:-1], "required") in errors(env)


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


def ses_without_from_addresses(env):
    del env["cloud"]["aws"]["ses"]["approved_from_addresses"]
    return ("cloud", "aws", "ses"), "required"


def empty_ses_from_addresses(env):
    env["cloud"]["aws"]["ses"]["approved_from_addresses"] = []
    return ("cloud", "aws", "ses", "approved_from_addresses"), "minItems"


def unknown_ses_key(env):
    env["cloud"]["aws"]["ses"]["configuration_sets"] = []
    return ("cloud", "aws", "ses"), "additionalProperties"


def duplicate_ses_from_address(env):
    addrs = env["cloud"]["aws"]["ses"]["approved_from_addresses"]
    addrs.append(addrs[0])
    return ("cloud", "aws", "ses", "approved_from_addresses"), "uniqueItems"


def ses_from_address_without_at(env):
    env["cloud"]["aws"]["ses"]["approved_from_addresses"][0] = "app-alerts"
    return ("cloud", "aws", "ses", "approved_from_addresses", 0), "pattern"


@pytest.mark.parametrize("mutate", [
    student_pii_without_regions, unknown_guardrail_mode, unknown_student_pii_key,
    privacy_block_is_not_a_key, empty_managed_identifiers,
    student_pii_without_permission_set, wildcard_permission_set, long_permission_set,
    ses_without_from_addresses, empty_ses_from_addresses, unknown_ses_key,
    duplicate_ses_from_address, ses_from_address_without_at,
])
def test_malformed_record_fails_at_the_named_key(mutate):
    env = copy.deepcopy(FULL)
    expected = mutate(env)
    assert expected in errors(env)


@pytest.mark.parametrize("value", ["*@<district-domain>", "app-?lerts@<district-domain>",
                                   "app alerts@<district-domain>", "a@b@<district-domain>"])
def test_ses_from_address_takes_no_wildcard_space_or_second_at(value):
    """ses_send.rego compares pins to the list as literals, so a * or ? entry would
    approve a StringLike pin of that same pattern."""
    env = copy.deepcopy(FULL)
    env["cloud"]["aws"]["ses"]["approved_from_addresses"][0] = value
    assert (("cloud", "aws", "ses", "approved_from_addresses", 0), "pattern") in errors(env)


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
