# ABOUTME: Checks schemas/iac/environment-file.schema.json against its placeholder example,
# ABOUTME: schemas/iac/example.env.yml, and that the retired org section stays rejected.
import copy
import json
import pathlib

import jsonschema
import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas/iac/environment-file.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
EXAMPLE = yaml.safe_load((ROOT / "schemas/iac/example.env.yml").read_text())


def test_example_env_file_satisfies_schema():
    jsonschema.validate(EXAMPLE, SCHEMA)


def test_schema_has_no_org_section():
    # Each account bootstraps its own Terraform state, so the management-account
    # alias the old hand-made state bucket needed is gone from the schema.
    doc = copy.deepcopy(EXAMPLE)
    doc["org"] = {"management_account_alias": "<management-account-alias>"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)


def test_schema_id_points_at_this_repo():
    assert SCHEMA["$id"] == (
        "https://raw.githubusercontent.com/PSD401/.github/main/"
        "schemas/iac/environment-file.schema.json"
    )
