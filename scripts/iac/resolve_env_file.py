#!/usr/bin/env python3
# ABOUTME: Resolves the decoded private environment file into backend.hcl and TF_VAR_/PKR_VAR_
# ABOUTME: exports for one plan or apply job, without printing a value.
"""Resolve the decoded private environment file for one plan/apply job.

Usage:
  resolve_env_file.py --env-file <decoded.env.yml> --github-env "$GITHUB_ENV"
      --platform aws|gcp --environment <env> --account-alias prod|nonprod|sandbox
      --repo <repo> --region <region> --backend-out <path>/backend.hcl
  resolve_env_file.py --env-file <decoded.env.yml> --github-env "$GITHUB_ENV"
      --platform proxmox --repo <repo>

aws:     writes backend.hcl (bucket = <state_bucket_prefix>-<account alias>-<region>,
         key = <repo>/<environment>/terraform.tfstate) and exports TF_VAR_repo,
         TF_VAR_account_alias, TF_VAR_alerts_topic_name,
         TF_VAR_bedrock_default_model_id (standards/08-iac.md 'Platform: AWS',
         'District defaults').
gcp:     exports TF_VAR_repo and TF_VAR_project_id (cloud.gcp.project_id).
proxmox: exports TF_VAR_/PKR_VAR_ pairs the proxmox-vm template's root module
         and Packer manifest declare (standards/15-onprem-platform.md §17).

Never prints a resolved value: errors name the missing key only.
"""
import argparse
import json
import sys

import yaml

ALIAS_TO_GCP = {"prod": "prod", "nonprod": "nonprod", "sandbox": "nonprod"}


class MissingKey(Exception):
    pass


def dig(data, *path):
    cur = data
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            raise MissingKey(".".join(path))
        cur = cur[p]
    return cur


def export(github_env, pairs):
    with open(github_env, "a", encoding="utf-8") as f:
        for name, value in pairs:
            if isinstance(value, (list, dict)):
                value = json.dumps(value, separators=(",", ":"))
            f.write(f"{name}={value}\n")


def aws(env, a):
    prefix = dig(env, "cloud", "aws", "state_bucket_prefix")
    alias = dig(env, "cloud", "aws", "account_alias", a.account_alias)
    with open(a.backend_out, "w", encoding="utf-8") as f:
        f.write(f'bucket = "{prefix}-{alias}-{a.region}"\n')
        f.write(f'key    = "{a.repo}/{a.environment}/terraform.tfstate"\n')
        f.write(f'region = "{a.region}"\n')
    return [
        ("TF_VAR_repo", a.repo),
        ("TF_VAR_account_alias", a.account_alias),
        ("TF_VAR_alerts_topic_name", dig(env, "cloud", "aws", "alerts_topic_name")),
        ("TF_VAR_bedrock_default_model_id", dig(env, "cloud", "aws", "bedrock_default_model_id")),
    ]


def gcp(env, a):
    return [
        ("TF_VAR_repo", a.repo),
        ("TF_VAR_project_id", dig(env, "cloud", "gcp", "project_id", ALIAS_TO_GCP[a.account_alias])),
    ]


def proxmox(env, a):
    endpoint = dig(env, "virtualization", "proxmox_api_endpoint")
    pool = dig(env, "virtualization", "resource_pools", a.repo)
    return [
        ("TF_VAR_proxmox_api_endpoint", endpoint),
        ("PKR_VAR_proxmox_api_endpoint", endpoint),
        ("TF_VAR_resource_pool", pool),
        ("PKR_VAR_resource_pool", pool),
        ("TF_VAR_dns_zone_internal", dig(env, "network", "dns_zones", "internal")),
        ("TF_VAR_syslog_target", dig(env, "network", "syslog_target")),
        ("TF_VAR_monitoring_server", dig(env, "monitoring", "zabbix_server")),
        ("TF_VAR_ntp_servers", dig(env, "network", "ntp_servers")),
        ("TF_VAR_patch_window", dig(env, "patch_window")),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", required=True)
    ap.add_argument("--github-env", required=True)
    ap.add_argument("--platform", required=True, choices=["aws", "gcp", "proxmox"])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--environment", default="")
    ap.add_argument("--account-alias", choices=["prod", "nonprod", "sandbox"], default="nonprod")
    ap.add_argument("--region", default="")
    ap.add_argument("--backend-out", default="backend.hcl")
    a = ap.parse_args()

    with open(a.env_file, encoding="utf-8") as f:
        env = yaml.safe_load(f)

    try:
        pairs = {"aws": aws, "gcp": gcp, "proxmox": proxmox}[a.platform](env, a)
    except MissingKey as exc:
        print(f"environment file has no {exc} (needed for platform {a.platform}, repo {a.repo}).",
              file=sys.stderr)
        return 1
    export(a.github_env, pairs)
    print(f"resolved {len(pairs)} value(s) for platform {a.platform} into GITHUB_ENV"
          + (f" and wrote {a.backend_out}" if a.platform == "aws" else "") + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
