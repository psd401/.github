# ABOUTME: Tests for resolve_env_file.py: backend.hcl and TF_VAR_/PKR_VAR_ exports from the
# ABOUTME: decoded environment file, without printing a value.
"""Tests for resolve_env_file.py: turn the decoded private environment file
into backend.hcl and TF_VAR_/PKR_VAR_ exports for one plan/apply job, without
printing a value, and reduce cloud.aws.student_pii to student-pii-account.json and
cloud.aws.ses to ses-from-addresses.json."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).parent
SCRIPT = HERE / "resolve_env_file.py"
ENV = HERE / "fixtures" / "district.example.yml"
PII_ENV = HERE / "fixtures" / "env-student-pii.yml"


def run(tmp_path, *args):
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(ENV),
                        "--github-env", str(github_env), *args],
                       capture_output=True, text=True)
    return r, github_env.read_text()


def test_aws_writes_backend_hcl_from_prefix_alias_and_region(tmp_path):
    out = tmp_path / "backend.hcl"
    r, _ = run(tmp_path, "--platform", "aws", "--environment", "dev", "--account-alias", "nonprod",
               "--repo", "my-app", "--region", "us-west-2", "--backend-out", str(out))
    assert r.returncode == 0, r.stderr
    assert out.read_text() == (
        'bucket = "example-tfstate-nonprod-alias-us-west-2"\n'
        'key    = "my-app/dev/terraform.tfstate"\n'
        'region = "us-west-2"\n')


def test_aws_exports_district_defaults_as_tf_vars(tmp_path):
    r, env = run(tmp_path, "--platform", "aws", "--environment", "prod", "--account-alias", "prod",
                 "--repo", "my-app", "--region", "us-west-2", "--backend-out", str(tmp_path / "b.hcl"))
    assert r.returncode == 0, r.stderr
    assert "TF_VAR_repo=my-app\n" in env
    assert "TF_VAR_account_alias=prod\n" in env
    assert "TF_VAR_alerts_topic_name=example-alerts\n" in env
    assert "TF_VAR_bedrock_default_model_id=anthropic.claude-x\n" in env


def test_gcp_exports_project_id_and_writes_no_backend(tmp_path):
    out = tmp_path / "backend.hcl"
    r, env = run(tmp_path, "--platform", "gcp", "--environment", "dev", "--account-alias", "nonprod",
                 "--repo", "my-app", "--region", "us-west1", "--backend-out", str(out))
    assert r.returncode == 0, r.stderr
    assert "TF_VAR_project_id=gcp-nonprod-project\n" in env
    assert not out.exists()


def test_proxmox_exports_tf_and_pkr_vars(tmp_path):
    r, env = run(tmp_path, "--platform", "proxmox", "--repo", "vm-repo")
    assert r.returncode == 0, r.stderr
    assert "TF_VAR_proxmox_api_endpoint=https://pve.example.internal:8006\n" in env
    assert "PKR_VAR_proxmox_api_endpoint=https://pve.example.internal:8006\n" in env
    assert "TF_VAR_resource_pool=pool-vm-repo\n" in env
    assert "PKR_VAR_resource_pool=pool-vm-repo\n" in env
    assert "TF_VAR_dns_zone_internal=example.internal\n" in env
    assert "TF_VAR_syslog_target=syslog.example.internal:514\n" in env
    assert "TF_VAR_monitoring_server=zabbix.example.internal\n" in env
    assert 'TF_VAR_ntp_servers=["ntp1.example.internal","ntp2.example.internal"]\n' in env
    assert "TF_VAR_patch_window=Sun 02:00-04:00\n" in env


def test_proxmox_repo_without_a_pool_fails_without_printing_values(tmp_path):
    r, env = run(tmp_path, "--platform", "proxmox", "--repo", "unknown-repo")
    assert r.returncode == 1
    assert "resource_pools" in r.stderr
    assert "pool-vm-repo" not in r.stderr + r.stdout
    assert env == ""


def test_never_prints_a_value(tmp_path):
    r, _ = run(tmp_path, "--platform", "aws", "--environment", "dev", "--account-alias", "nonprod",
               "--repo", "my-app", "--region", "us-west-2", "--backend-out", str(tmp_path / "b.hcl"))
    assert "nonprod-alias" not in r.stdout + r.stderr
    assert "example-alerts" not in r.stdout + r.stderr


def run_account(tmp_path, env_file=PII_ENV):
    """--student-pii-out alone, without --github-env or --platform."""
    out = tmp_path / "student-pii-account.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env_file),
                        "--student-pii-out", str(out), "--repo", "sis-sync"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r, out.read_text()


def mutated(tmp_path, mutate):
    env = yaml.safe_load(PII_ENV.read_text())
    mutate(env)
    out = tmp_path / "env.yml"
    out.write_text(yaml.safe_dump(env))
    return out


def test_needs_platform_or_student_pii_out(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(PII_ENV),
                        "--repo", "sis-sync"], capture_output=True, text=True)
    assert r.returncode == 2
    assert "--student-pii-out" in r.stderr


@pytest.mark.parametrize("args, named", [
    (["--platform", "aws"], "--github-env"),
    (["--github-env", "github_env"], "--platform"),
])
def test_github_env_and_platform_go_together(tmp_path, args, named):
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(PII_ENV),
                        "--repo", "sis-sync", *args],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2
    assert named in r.stderr


def test_student_pii_out_runs_alongside_a_platform(tmp_path):
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    out = tmp_path / "student-pii-account.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(PII_ENV),
                        "--github-env", str(github_env), "--platform", "aws",
                        "--environment", "dev", "--account-alias", "nonprod", "--repo", "sis-sync",
                        "--region", "us-west-2", "--backend-out", str(tmp_path / "b.hcl"),
                        "--student-pii-out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["student_pii_account"]["present"] is True
    assert "TF_VAR_repo=sis-sync\n" in github_env.read_text()


def test_malformed_yaml_fails_without_quoting_the_file(tmp_path):
    secret = "hunter2-not-a-real-secret"
    bad = tmp_path / "bad.env.yml"
    bad.write_text(f"oidc:\n  token: {secret}\n    broken: [\n")
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(bad),
                        "--student-pii-out", str(tmp_path / "a.json"),
                        "--repo", "sis-sync"], capture_output=True, text=True)
    assert r.returncode == 1
    assert secret not in r.stdout + r.stderr
    assert "not valid YAML" in r.stderr
    assert "Traceback" not in r.stderr
    assert not (tmp_path / "a.json").exists()


ACCT_FIXTURE = HERE.parents[1] / "policy" / "conftest" / "fixtures" / "aws" / "acct_student_pii_account.json"


def account(tmp_path, env_file=PII_ENV):
    return json.loads(run_account(tmp_path, env_file)[1])["student_pii_account"]


def test_student_pii_out_carries_the_account_controls_the_rego_compares_against(tmp_path):
    """account_controls.rego and unmask.rego read data.student_pii_account. The
    rego tests bind the same fixture, so the two cannot drift apart."""
    expected = json.loads(ACCT_FIXTURE.read_text())["acct_student_pii_account"]
    assert account(tmp_path) == expected


def test_account_controls_without_cloud_aws_student_pii_are_present_false(tmp_path):
    assert account(tmp_path, ENV) == {"present": False, "breakglass_role_name": "",
                                      "breakglass_permission_set_name": "",
                                      "managed_identifiers": [], "custom_identifier_names": []}


def test_account_controls_default_the_managed_identifiers_like_the_baseline(tmp_path):
    """modules/student-pii-account-baseline applies the same three when unset."""
    env = mutated(tmp_path, lambda e: e["cloud"]["aws"]["student_pii"].pop("managed_identifiers"))
    assert account(tmp_path, env)["managed_identifiers"] == [
        "arn:aws:dataprotection::aws:data-identifier/Name",
        "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
        "arn:aws:dataprotection::aws:data-identifier/Address",
    ]


def test_account_controls_never_carry_a_custom_identifier_regex_or_test_string(tmp_path):
    _, text = run_account(tmp_path)
    for ident in yaml.safe_load(PII_ENV.read_text())["cloud"]["aws"]["student_pii"]["custom_identifiers"]:
        for secret in [ident["regex"], *ident.get("test_matches", []), *ident.get("test_non_matches", [])]:
            assert json.dumps(secret)[1:-1] not in text and secret not in text


def aws_exports(tmp_path, env_file):
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env_file),
                        "--github-env", str(github_env), "--platform", "aws",
                        "--environment", "prod", "--account-alias", "prod", "--repo", "account-baseline",
                        "--region", "us-west-2", "--backend-out", str(tmp_path / "b.hcl")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return dict(line.split("=", 1) for line in github_env.read_text().splitlines())


def test_aws_exports_the_deploy_role_prefix_for_the_baseline_apply_role_name(tmp_path):
    assert aws_exports(tmp_path, ENV)["TF_VAR_deploy_role_prefix"] == "example-deploy"


def test_aws_exports_student_pii_trimmed_to_what_the_account_baseline_root_reads(tmp_path):
    """templates/account-baseline declares var.student_pii. GITHUB_ENV values
    show in later steps' log headers, so test strings, applications and
    guardrail_mode stay out."""
    exported = json.loads(aws_exports(tmp_path, PII_ENV)["TF_VAR_student_pii"])
    source = yaml.safe_load(PII_ENV.read_text())["cloud"]["aws"]["student_pii"]
    assert exported == {
        "regions": source["regions"],
        "breakglass_role_name": source["breakglass_role_name"],
        "breakglass_permission_set_name": source["breakglass_permission_set_name"],
        "managed_identifiers": source["managed_identifiers"],
        "custom_identifiers": [{"name": c["name"], "regex": c["regex"]}
                               for c in source["custom_identifiers"]],
    }
    text = json.dumps(exported)
    for c in source["custom_identifiers"]:
        for s in c["test_matches"] + c["test_non_matches"]:
            assert s not in text


def test_aws_exports_no_student_pii_without_cloud_aws_student_pii(tmp_path):
    assert "TF_VAR_student_pii" not in aws_exports(tmp_path, ENV)


SES_FIXTURE = HERE.parents[1] / "policy" / "conftest" / "fixtures" / "aws" / "ses_env_from_addresses.json"


def run_ses(tmp_path, env_file=PII_ENV):
    """--ses-out alone, without --github-env or --platform."""
    out = tmp_path / "ses-from-addresses.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(env_file),
                        "--ses-out", str(out), "--repo", "sis-sync"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r, json.loads(out.read_text())["ses_from_addresses"]


def test_ses_out_carries_the_approved_list_the_rego_compares_against(tmp_path):
    """ses_send.rego reads data.ses_from_addresses. The rego tests bind the same
    fixture, so the two cannot drift apart."""
    expected = json.loads(SES_FIXTURE.read_text())["ses_env_from_addresses"]
    assert run_ses(tmp_path)[1] == expected


def test_ses_out_without_cloud_aws_ses_is_present_false(tmp_path):
    assert run_ses(tmp_path, ENV)[1] == {"present": False, "approved_from_addresses": []}


@pytest.mark.parametrize("ses_block, expected", [
    ("{}", []),
    ("{approved_from_addresses: app-alerts@<district-domain>}", []),
    ("{approved_from_addresses: [7, app-alerts@<district-domain>, null]}", ["app-alerts@<district-domain>"]),
])
def test_ses_out_with_a_malformed_ses_block_keeps_only_string_entries(tmp_path, ses_block, expected):
    """The resolver does not validate against the schema. An ses block with no
    list, a value that is not a list, or entries that are not strings comes out
    present with only the string entries, and ses_send.rego denies a pinned
    statement when that list is empty."""
    env = tmp_path / "env.yml"
    env.write_text(f"cloud:\n  aws:\n    ses: {ses_block}\n")
    assert run_ses(tmp_path, env)[1] == {"present": True, "approved_from_addresses": expected}


def test_ses_out_never_prints_an_address(tmp_path):
    r, _ = run_ses(tmp_path)
    for addr in yaml.safe_load(PII_ENV.read_text())["cloud"]["aws"]["ses"]["approved_from_addresses"]:
        assert addr not in r.stdout + r.stderr


def test_ses_out_runs_alongside_a_platform_and_the_student_pii_file(tmp_path):
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    ses, pii = tmp_path / "ses-from-addresses.json", tmp_path / "student-pii-account.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(PII_ENV),
                        "--github-env", str(github_env), "--platform", "aws",
                        "--environment", "dev", "--account-alias", "nonprod", "--repo", "sis-sync",
                        "--region", "us-west-2", "--backend-out", str(tmp_path / "b.hcl"),
                        "--student-pii-out", str(pii), "--ses-out", str(ses)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(ses.read_text())["ses_from_addresses"]["present"] is True
    assert json.loads(pii.read_text())["student_pii_account"]["present"] is True
    assert "TF_VAR_repo=sis-sync\n" in github_env.read_text()
    assert "@<district-domain>" not in github_env.read_text()


def test_needs_an_output_names_ses_out(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(PII_ENV),
                        "--repo", "sis-sync"], capture_output=True, text=True)
    assert r.returncode == 2
    assert "--ses-out" in r.stderr


def test_malformed_yaml_writes_no_ses_file(tmp_path):
    bad = tmp_path / "bad.env.yml"
    bad.write_text("cloud:\n  aws: [\n")
    r = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(bad),
                        "--ses-out", str(tmp_path / "s.json"), "--repo", "sis-sync"],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert not (tmp_path / "s.json").exists()
