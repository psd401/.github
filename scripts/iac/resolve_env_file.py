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
  resolve_env_file.py --env-file <decoded.env.yml> --student-pii-out <path>/student-pii-account.json
      --ses-out <path>/ses-from-addresses.json --repo <repo>

aws:     writes backend.hcl (bucket = <state_bucket_prefix>-<account alias>-<region>,
         key = <repo>/<environment>/terraform.tfstate) and exports TF_VAR_repo,
         TF_VAR_account_alias, TF_VAR_alerts_topic_name,
         TF_VAR_bedrock_default_model_id, TF_VAR_deploy_role_prefix and, when
         cloud.aws.student_pii is set, TF_VAR_student_pii without its test
         strings (templates/account-baseline; standards/08-iac.md 'Platform: AWS',
         'District defaults').
gcp:     exports TF_VAR_repo and TF_VAR_project_id (cloud.gcp.project_id).
proxmox: exports TF_VAR_/PKR_VAR_ pairs the proxmox-vm template's root module
         and Packer manifest declare (standards/15-onprem-platform.md §17).
--student-pii-out: writes {"student_pii_account": ...}, cloud.aws.student_pii
         reduced to the break-glass role and permission set names and the
         identifier ARNs and names, for account_controls.rego and unmask.rego
         (standards/08-iac.md 'Student PII account posture'). Always written;
         present is false when the env file has no cloud.aws.student_pii. It
         never carries a custom identifier regex or test string. May run alone
         or alongside a --platform mode.
--ses-out: writes {"ses_from_addresses": {"present", "approved_from_addresses"}},
         cloud.aws.ses.approved_from_addresses, for ses_send.rego's
         ses:FromAddress check (standards/17-email-sending.md rules 3 and 9).
         Always written; present is false and the list empty when the env file
         has no cloud.aws.ses. May run alone or alongside the other modes.

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
    pairs = [
        ("TF_VAR_repo", a.repo),
        ("TF_VAR_account_alias", a.account_alias),
        ("TF_VAR_alerts_topic_name", dig(env, "cloud", "aws", "alerts_topic_name")),
        ("TF_VAR_bedrock_default_model_id", dig(env, "cloud", "aws", "bedrock_default_model_id")),
        ("TF_VAR_deploy_role_prefix", dig(env, "oidc", "deploy_role_prefix")),
    ]
    student_pii = baseline_student_pii(env)
    if student_pii is not None:
        pairs.append(("TF_VAR_student_pii", student_pii))
    return pairs


def baseline_student_pii(env):
    """cloud.aws.student_pii reduced to the keys templates/account-baseline
    declares, or None without it. GITHUB_ENV values show in later steps' log
    headers, so test strings and guardrail_mode stay out."""
    sp = dig(env, "cloud", "aws").get("student_pii")
    if not isinstance(sp, dict):
        return None
    out = {
        "regions": sp.get("regions"),
        "breakglass_role_name": sp.get("breakglass_role_name"),
        "breakglass_permission_set_name": sp.get("breakglass_permission_set_name"),
        "custom_identifiers": [{"name": c.get("name"), "regex": c.get("regex")}
                               for c in sp.get("custom_identifiers") or [] if isinstance(c, dict)],
    }
    if "managed_identifiers" in sp:
        out["managed_identifiers"] = sp["managed_identifiers"]
    return out


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


# modules/student-pii-account-baseline applies the same default when
# managed_identifiers is unset.
DEFAULT_MANAGED_IDENTIFIERS = [
    "arn:aws:dataprotection::aws:data-identifier/Name",
    "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
    "arn:aws:dataprotection::aws:data-identifier/Address",
]


def student_pii_account(env):
    """cloud.aws.student_pii reduced for account_controls.rego and unmask.rego."""
    aws = ((env.get("cloud") or {}).get("aws") or {}) if isinstance(env, dict) else {}
    sp = aws.get("student_pii") if isinstance(aws, dict) else None
    if not isinstance(sp, dict):
        return {"present": False, "breakglass_role_name": "", "breakglass_permission_set_name": "",
                "managed_identifiers": [], "custom_identifier_names": []}
    role = sp.get("breakglass_role_name")
    permission_set = sp.get("breakglass_permission_set_name")
    managed = sp.get("managed_identifiers", DEFAULT_MANAGED_IDENTIFIERS)
    custom = sp.get("custom_identifiers")
    return {
        "present": True,
        "breakglass_role_name": role if isinstance(role, str) else "",
        "breakglass_permission_set_name": permission_set if isinstance(permission_set, str) else "",
        "managed_identifiers": [m for m in managed if isinstance(m, str)] if isinstance(managed, list) else [],
        "custom_identifier_names": [c["name"] for c in custom
                                    if isinstance(c, dict) and isinstance(c.get("name"), str)]
                                   if isinstance(custom, list) else [],
    }


def write_student_pii_account(env, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"student_pii_account": student_pii_account(env)}, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path}.")


def ses_from_addresses(env):
    """cloud.aws.ses.approved_from_addresses for ses_send.rego; non-string entries dropped."""
    aws = ((env.get("cloud") or {}).get("aws") or {}) if isinstance(env, dict) else {}
    ses = aws.get("ses") if isinstance(aws, dict) else None
    if not isinstance(ses, dict):
        return {"present": False, "approved_from_addresses": []}
    addrs = ses.get("approved_from_addresses")
    return {
        "present": True,
        "approved_from_addresses": [x for x in addrs if isinstance(x, str)] if isinstance(addrs, list) else [],
    }


def write_ses_from_addresses(env, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"ses_from_addresses": ses_from_addresses(env)}, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path}.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", required=True)
    ap.add_argument("--github-env")
    ap.add_argument("--platform", choices=["aws", "gcp", "proxmox"])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--environment", default="")
    ap.add_argument("--account-alias", choices=["prod", "nonprod", "sandbox"], default="nonprod")
    ap.add_argument("--region", default="")
    ap.add_argument("--backend-out", default="backend.hcl")
    ap.add_argument("--student-pii-out")
    ap.add_argument("--ses-out")
    a = ap.parse_args()
    if (a.github_env is None) != (a.platform is None):
        ap.error("--github-env and --platform go together.")
    if a.platform is None and a.student_pii_out is None and a.ses_out is None:
        ap.error("give --github-env with --platform, --student-pii-out, --ses-out, or any mix.")

    try:
        with open(a.env_file, encoding="utf-8") as f:
            env = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        # PyYAML's message quotes the offending line, which may hold a secret.
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        print(f"environment file is not valid YAML{where}.", file=sys.stderr)
        return 1

    if a.student_pii_out is not None:
        write_student_pii_account(env, a.student_pii_out)
    if a.ses_out is not None:
        write_ses_from_addresses(env, a.ses_out)
    if a.platform is None:
        return 0

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
