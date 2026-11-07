# ABOUTME: Tests for resolve_env_file.py: backend.hcl and TF_VAR_/PKR_VAR_ exports from the
# ABOUTME: decoded environment file, without printing a value.
"""Tests for resolve_env_file.py: turn the decoded private environment file
into backend.hcl and TF_VAR_/PKR_VAR_ exports for one plan/apply job, without
printing a value."""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
SCRIPT = HERE / "resolve_env_file.py"
ENV = HERE / "fixtures" / "district.example.yml"


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
