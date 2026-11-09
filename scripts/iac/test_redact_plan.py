# ABOUTME: Tests for redact_plan.py: every section of a plan JSON that can carry a
# ABOUTME: sensitive value is masked before upload.
"""Tests for redact_plan.py: every section of a `terraform show -json` plan
that can carry a sensitive value is masked before the JSON is uploaded."""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("redact_plan.py")


def run(tmp_path, plan):
    raw = tmp_path / "tfplan.raw.json"
    out = tmp_path / "tfplan.json"
    raw.write_text(json.dumps(plan))
    subprocess.run([sys.executable, str(SCRIPT), str(raw), str(out)], check=True)
    return json.loads(out.read_text())


def test_resource_changes_after_is_masked(tmp_path):
    plan = {"resource_changes": [{"address": "a", "change": {
        "after": {"password": "hunter2", "name": "db"},
        "after_sensitive": {"password": True}}}]}
    got = run(tmp_path, plan)
    assert got["resource_changes"][0]["change"]["after"] == {"password": None, "name": "db"}


def test_planned_values_are_masked_including_child_modules(tmp_path):
    plan = {"planned_values": {"root_module": {
        "resources": [{"address": "a", "values": {"password": "hunter2", "name": "db"},
                       "sensitive_values": {"password": True}}],
        "child_modules": [{"address": "module.m", "resources": [
            {"address": "module.m.b", "values": {"token": "t0k", "port": 5432},
             "sensitive_values": {"token": True}}]}]}}}
    got = run(tmp_path, plan)
    root = got["planned_values"]["root_module"]
    assert root["resources"][0]["values"] == {"password": None, "name": "db"}
    assert root["child_modules"][0]["resources"][0]["values"] == {"token": None, "port": 5432}


def test_output_changes_are_masked(tmp_path):
    plan = {"output_changes": {
        "db_password": {"before": "old", "after": "new", "before_sensitive": True, "after_sensitive": True},
        "url": {"before": "u1", "after": "u2", "before_sensitive": False, "after_sensitive": False}}}
    got = run(tmp_path, plan)
    assert got["output_changes"]["db_password"]["after"] is None
    assert got["output_changes"]["db_password"]["before"] is None
    assert got["output_changes"]["url"]["after"] == "u2"


def test_configuration_literals_are_masked_by_planned_sensitivity(tmp_path):
    plan = {
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_db_instance.a", "values": {"password": "hunter2"},
             "sensitive_values": {"password": True}}]}},
        "configuration": {
            "provider_config": {"aws": {"expressions": {
                "region": {"constant_value": "us-west-2"},
                "secret_key": {"constant_value": "AKIA..."}}}},
            "root_module": {"resources": [
                {"address": "aws_db_instance.a", "expressions": {
                    "password": {"constant_value": "hunter2"},
                    "engine": {"constant_value": "postgres"}}}]}}}
    got = run(tmp_path, plan)
    res = got["configuration"]["root_module"]["resources"][0]["expressions"]
    assert res["password"]["constant_value"] is None
    assert res["engine"]["constant_value"] == "postgres"
    prov = got["configuration"]["provider_config"]["aws"]["expressions"]
    assert prov["secret_key"]["constant_value"] is None
    assert prov["region"]["constant_value"] == "us-west-2"


def test_prior_state_variables_and_drift_values_do_not_leak(tmp_path):
    plan = {"prior_state": {"values": {"x": "secret"}},
            "variables": {"db_password": {"value": "hunter2"}},
            "resource_drift": [{"address": "a", "change": {
                "before": {"password": "old"}, "before_sensitive": {"password": True},
                "after": {"password": "new"}, "after_sensitive": {"password": True}}}]}
    got = run(tmp_path, plan)
    assert "prior_state" not in got
    assert "variables" not in got
    assert got["resource_drift"][0]["change"]["before"] == {"password": None}
    assert got["resource_drift"][0]["change"]["after"] == {"password": None}


def test_nothing_sensitive_passes_through_unchanged(tmp_path):
    plan = {"format_version": "1.2", "resource_changes": [{"address": "a", "change": {
        "after": {"name": "db"}, "after_sensitive": {}}}]}
    assert run(tmp_path, plan) == plan


def test_configuration_nested_block_literals_are_masked(tmp_path):
    plan = {
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_x.a", "values": {"auth": [{"secret": "s", "mode": "m"}]},
             "sensitive_values": {"auth": [{"secret": True}]}}]}},
        "configuration": {"root_module": {"resources": [
            {"address": "aws_x.a", "expressions": {"auth": [
                {"secret": {"constant_value": "s"}, "mode": {"constant_value": "m"}}]}}]}}}
    got = run(tmp_path, plan)
    block = got["configuration"]["root_module"]["resources"][0]["expressions"]["auth"][0]
    assert block["secret"]["constant_value"] is None
    assert block["mode"]["constant_value"] == "m"


def test_count_and_for_each_instances_still_mask_configuration_literals(tmp_path):
    plan = {
        "planned_values": {"root_module": {
            "resources": [{"address": "aws_db_instance.a[0]", "values": {"password": "hunter2"},
                           "sensitive_values": {"password": True}},
                          {"address": "aws_db_instance.a[1]", "values": {"password": "hunter3"},
                           "sensitive_values": {"password": True}}],
            "child_modules": [{"address": "module.m[\"x\"]", "resources": [
                {"address": "module.m[\"x\"].aws_x.b", "values": {"token": "t"},
                 "sensitive_values": {"token": True}}]}]}},
        "configuration": {"root_module": {
            "resources": [{"address": "aws_db_instance.a", "expressions": {
                "password": {"constant_value": "hunter2"}, "count": {"constant_value": 2}}}],
            "module_calls": {"m": {"module": {"resources": [
                {"address": "aws_x.b", "expressions": {"token": {"constant_value": "t"}}}]}}}}}}
    got = run(tmp_path, plan)
    root = got["configuration"]["root_module"]
    assert root["resources"][0]["expressions"]["password"]["constant_value"] is None
    assert root["resources"][0]["expressions"]["count"]["constant_value"] == 2
    assert root["module_calls"]["m"]["module"]["resources"][0]["expressions"]["token"]["constant_value"] is None


def test_module_call_arguments_are_masked(tmp_path):
    plan = {"configuration": {"root_module": {"module_calls": {"db": {
        "expressions": {
            "master_password": {"constant_value": "hunter2"},
            "admin_pw": {"constant_value": "hunter3"},
            "engine": {"constant_value": "postgres"}},
        "module": {"variables": {
            "admin_pw": {"sensitive": True},
            "engine": {}}}}}}}}
    got = run(tmp_path, plan)
    args = got["configuration"]["root_module"]["module_calls"]["db"]["expressions"]
    assert args["master_password"]["constant_value"] is None  # secret-shaped name
    assert args["admin_pw"]["constant_value"] is None  # variable declared sensitive
    assert args["engine"]["constant_value"] == "postgres"


def test_configuration_variable_defaults_and_outputs_are_masked(tmp_path):
    plan = {"configuration": {"root_module": {
        "variables": {"db_password": {"default": "hunter2", "sensitive": True},
                      "api_key": {"default": "k"},
                      "region": {"default": "us-west-2"}},
        "outputs": {"pw": {"sensitive": True, "expression": {"constant_value": "hunter2"}},
                    "url": {"expression": {"constant_value": "https://x"}}}}}}
    got = run(tmp_path, plan)
    root = got["configuration"]["root_module"]
    assert root["variables"]["db_password"]["default"] is None
    assert root["variables"]["api_key"]["default"] is None  # secret-shaped name
    assert root["variables"]["region"]["default"] == "us-west-2"
    assert root["outputs"]["pw"]["expression"]["constant_value"] is None
    assert root["outputs"]["url"]["expression"]["constant_value"] == "https://x"


def test_planned_outputs_are_masked(tmp_path):
    plan = {"planned_values": {
        "outputs": {"pw": {"sensitive": True, "value": "hunter2"},
                    "url": {"sensitive": False, "value": "https://x"}},
        "root_module": {}}}
    got = run(tmp_path, plan)
    assert got["planned_values"]["outputs"]["pw"]["value"] is None
    assert got["planned_values"]["outputs"]["url"]["value"] == "https://x"


def test_no_sentinel_survives_anywhere(tmp_path):
    """Every shape above in one plan: the sentinel string must not appear in the output at all."""
    S = "SENTINEL_hunter2"
    plan = {
        "planned_values": {
            "outputs": {"pw": {"sensitive": True, "value": S}},
            "root_module": {"resources": [
                {"address": "aws_db_instance.a[0]", "values": {"password": S},
                 "sensitive_values": {"password": True}}]}},
        "output_changes": {"pw": {"after": S, "after_sensitive": True}},
        "resource_changes": [{"address": "aws_db_instance.a[0]", "change": {
            "after": {"password": S}, "after_sensitive": {"password": True}}}],
        "configuration": {
            "provider_config": {"aws": {"expressions": {"secret_key": {"constant_value": S}}}},
            "root_module": {
                "variables": {"db_password": {"default": S, "sensitive": True}},
                "outputs": {"pw": {"sensitive": True, "expression": {"constant_value": S}}},
                "resources": [{"address": "aws_db_instance.a", "expressions": {
                    "password": {"constant_value": S}}}],
                "module_calls": {"m": {"expressions": {"secret": {"constant_value": S}},
                                       "module": {}}}}},
        "prior_state": {"values": S},
        "variables": {"db_password": {"value": S}}}
    assert S not in json.dumps(run(tmp_path, plan))


def test_data_source_literals_are_masked(tmp_path):
    """Terraform writes a data block's address as data.<type>.<name> in both
    planned_values and configuration (internal/addrs/resource.go String()),
    so the sensitivity lookup matches without a mode-specific prefix."""
    S = "SENTINEL_hunter2"
    plan = {
        "planned_values": {"root_module": {"resources": [
            {"address": "data.vault_generic_secret.db", "mode": "data",
             "values": {"token": S, "path": "secret/db"},
             "sensitive_values": {"token": True}}]}},
        "configuration": {"root_module": {"resources": [
            {"address": "data.vault_generic_secret.db", "mode": "data", "expressions": {
                "token": {"constant_value": S}, "path": {"constant_value": "secret/db"}}}]}}}
    got = run(tmp_path, plan)
    expr = got["configuration"]["root_module"]["resources"][0]["expressions"]
    assert expr["token"]["constant_value"] is None
    assert expr["path"]["constant_value"] == "secret/db"
    assert S not in json.dumps(got)
