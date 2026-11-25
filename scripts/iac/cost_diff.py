#!/usr/bin/env python3
# ABOUTME: Prices a redacted `terraform show -json` plan against prices/aws/<region>.json and
# ABOUTME: writes the monthly cost diff as Markdown for the PR comment (12-cloud-cost.md rule 12).
"""Monthly cost diff for a Terraform plan, from AWS list prices. No service, no key.

Usage:
  cost_diff.py --plan tfplan.json --prices-dir prices/aws --platform aws [--out cost.md]

Prices only what has a fixed monthly cost from its configuration: instances,
volumes, databases, Aurora Serverless v2's minimum capacity, NAT gateways,
public IPv4 addresses, load balancers, interface endpoints, alarms, secrets,
KMS keys, hosted zones and provisioned DynamoDB capacity. Everything billed by
use (Lambda, S3, SQS, logs, data transfer, requests, LCUs) is listed by name
and left out of the totals, because the plan says nothing about use.

Assumptions, printed under every table: on-demand list price, 730 hours a
month, Linux for an EC2 instance unless --windows names it, no free tier,
Savings Plans, credits or tax.

Exit status is 0 whenever a diff was written; the job is non-blocking.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HOURS = 730
MARKER = "<!-- psd-cost-diff -->"

# Billed only by use: listed, never totalled.
USAGE_BASED = {
    "aws_lambda_function", "aws_s3_bucket", "aws_sqs_queue", "aws_sns_topic", "aws_cloudwatch_log_group",
    "aws_api_gateway_rest_api", "aws_apigatewayv2_api", "aws_ecr_repository", "aws_sfn_state_machine",
    "aws_scheduler_schedule", "aws_cloudfront_distribution", "aws_amplify_app", "aws_amplify_branch",
    "aws_bedrock_inference_profile", "aws_xray_sampling_rule", "aws_kinesis_firehose_delivery_stream",
    "aws_ecs_service", "aws_ecs_task_definition", "aws_sesv2_configuration_set", "aws_cloudwatch_event_bus",
    "aws_wafv2_web_acl", "aws_dynamodb_table",  # dynamodb: provisioned mode is priced below
}
# No charge of their own (permissions, wiring, network plumbing, tags).
FREE_PREFIXES = ("aws_iam_", "aws_s3_bucket_", "aws_vpc_security_group_", "aws_ssm_parameter",
                 "aws_lambda_permission", "aws_lambda_event_source_mapping", "aws_cloudwatch_event_",
                 "aws_sns_topic_", "aws_sqs_queue_", "aws_route", "aws_route53_record", "aws_ecr_lifecycle_policy",
                 "aws_ecr_repository_policy", "aws_secretsmanager_secret_version", "aws_secretsmanager_secret_policy",
                 "aws_kms_alias", "aws_apigatewayv2_", "aws_api_gateway_", "aws_db_subnet_group",
                 "aws_db_parameter_group", "aws_rds_cluster_parameter_group", "aws_security_group",
                 "aws_subnet", "aws_vpc", "aws_internet_gateway", "aws_network_acl", "aws_default_",
                 "aws_cloudwatch_dashboard", "aws_cloudwatch_log_", "aws_scheduler_schedule_group",
                 "aws_sesv2_configuration_set_event_destination", "aws_xray_", "aws_amplify_",
                 "aws_budgets_", "aws_ce_", "aws_sns_", "aws_lb_listener", "aws_lb_target_group",
                 "aws_appautoscaling_", "aws_eip_association", "aws_key_pair", "aws_launch_template",
                 "aws_kms_key_policy", "aws_ecs_cluster", "aws_bedrock_", "aws_rds_cluster",
                 "aws_db_instance_automated_backups_replication", "random_", "null_", "terraform_data",
                 "time_", "tls_", "archive_", "local_")


@dataclass
class Cost:
    monthly: float | None  # None: couldn't be priced from the plan
    basis: str


@dataclass
class Row:
    address: str
    action: str
    before: Cost | None
    after: Cost | None


@dataclass
class Report:
    region: str
    rows: list[Row] = field(default_factory=list)
    usage: list[str] = field(default_factory=list)
    uncovered: dict[str, int] = field(default_factory=dict)


def money(x: float | None) -> str:
    if x is None:
        return "?"
    return f"${x:,.2f}"


def first(v):
    """Terraform nested blocks are lists; return the first element or {}."""
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], dict) else {}
    return v if isinstance(v, dict) else {}


class Pricer:
    def __init__(self, prices_dir: Path, default_region: str, windows: set[str]):
        self.dir = prices_dir
        self.default_region = default_region
        self.windows = windows
        self.tables: dict[str, dict] = {}
        self.serverless_min: dict[str, float] = {}  # cluster_identifier -> min ACU
        self.serverless_io: dict[str, bool] = {}
        self.only_cluster_min: float | None = None

    def table(self, region: str) -> dict | None:
        if region not in self.tables:
            path = self.dir / f"{region}.json"
            self.tables[region] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        return self.tables[region]

    def index_clusters(self, changes: list[dict]) -> None:
        """Aurora Serverless v2 bills a cluster's instances at the cluster's minimum ACU."""
        mins = []
        for rc in changes:
            if rc.get("type") != "aws_rds_cluster":
                continue
            after = rc["change"].get("after") or rc["change"].get("before") or {}
            scaling = first(after.get("serverlessv2_scaling_configuration"))
            if "min_capacity" in scaling and scaling["min_capacity"] is not None:
                ident = after.get("cluster_identifier")
                if isinstance(ident, str):
                    self.serverless_min[ident] = float(scaling["min_capacity"])
                    self.serverless_io[ident] = after.get("storage_type") == "aurora-iopt1"
                mins.append(float(scaling["min_capacity"]))
        if len(mins) == 1:
            self.only_cluster_min = mins[0]

    def price(self, rtype: str, v: dict, address: str) -> Cost | None:
        """Monthly cost of one resource state, or None when the type has no fixed price."""
        region = v.get("region") if isinstance(v.get("region"), str) else self.default_region
        t = self.table(region)
        if t is None:
            return Cost(None, f"no price table for {region}")
        fn = getattr(self, "_" + rtype, None)
        if fn is None:
            return None
        try:
            return fn(t, v, address)
        except (KeyError, TypeError, ValueError):
            return Cost(None, "not in the price list")

    # --- one method per priced type: (table, state, address) -> Cost -----------

    def _ebs(self, t, vtype, size, iops=None, throughput=None):
        vtype = vtype or "gp3"
        cost = t["ebs_gb_month"][vtype] * float(size)
        basis = f"{size} GB {vtype}"
        if vtype == "gp3":
            if iops and iops > 3000:
                cost += (iops - 3000) * t["ebs_iops_month"]["gp3"]
                basis += f", {iops} IOPS"
            if throughput and throughput > 125:
                cost += (throughput - 125) * t["ebs_gp3_throughput_mibps_month"]
                basis += f", {throughput} MiB/s"
        elif vtype in ("io1", "io2") and iops:
            cost += iops * t["ebs_iops_month"][vtype]
            basis += f", {iops} IOPS"
        return cost, basis

    def _aws_instance(self, t, v, address):
        os_name = "Windows" if address in self.windows else "Linux"
        itype = v["instance_type"]
        if v.get("tenancy") in ("dedicated", "host"):
            return Cost(None, f"{itype}, {v['tenancy']} tenancy is not priced")
        cost = t["ec2_instance_hourly"][os_name][itype] * HOURS
        parts = [f"{itype} {os_name}"]
        for vol in [first(v.get("root_block_device"))] + list(v.get("ebs_block_device") or []):
            if vol and vol.get("volume_size"):
                c, b = self._ebs(t, vol.get("volume_type"), vol["volume_size"], vol.get("iops"), vol.get("throughput"))
                cost += c
                parts.append(b)
        return Cost(cost, " + ".join(parts))

    def _aws_ebs_volume(self, t, v, address):
        if not v.get("size"):
            return Cost(None, "size not known until apply")
        c, b = self._ebs(t, v.get("type"), v["size"], v.get("iops"), v.get("throughput"))
        return Cost(c, b)

    def _aws_db_instance(self, t, v, address):
        engine = {"postgres": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB"}[v["engine"]]
        deploy = "Multi-AZ" if v.get("multi_az") else "Single-AZ"
        cls = v["instance_class"]
        cost = t["rds_instance_hourly"][engine][deploy][cls] * HOURS
        basis = f"{cls} {engine} {deploy}"
        storage = v.get("allocated_storage")
        if storage:
            stype = v.get("storage_type") or "gp2"
            cost += t["rds_storage_gb_month"][engine][deploy][stype] * float(storage)
            basis += f" + {storage} GB {stype}"
        return Cost(cost, basis)

    def _aws_rds_cluster_instance(self, t, v, address):
        engine = {"aurora-postgresql": "Aurora PostgreSQL", "aurora-mysql": "Aurora MySQL"}[v["engine"]]
        cls = v["instance_class"]
        if cls == "db.serverless":
            ident = v.get("cluster_identifier")
            acu = self.serverless_min.get(ident) if isinstance(ident, str) else None
            io = self.serverless_io.get(ident, False) if isinstance(ident, str) else False
            if acu is None:
                acu = self.only_cluster_min
            if acu is None:
                return Cost(None, "Serverless v2: cluster's minimum capacity not found")
            rate = t["aurora_serverless_v2_acu_hourly"][engine]["io_optimized" if io else "standard"]
            return Cost(acu * rate * HOURS, f"Serverless v2 floor, {acu:g} ACU minimum (more under load)")
        return Cost(t["rds_instance_hourly"][engine]["Single-AZ"][cls] * HOURS, f"{cls} {engine}")

    def _aws_nat_gateway(self, t, v, address):
        return Cost(t["nat_gateway_hourly"] * HOURS, "NAT gateway hours (data processed is extra)")

    def _aws_eip(self, t, v, address):
        return Cost(t["public_ipv4_hourly"] * HOURS, "public IPv4 address")

    def _aws_lb(self, t, v, address):
        kind = v.get("load_balancer_type") or "application"
        return Cost(t["elb_hourly"][kind] * HOURS, f"{kind} load balancer hours (LCUs are extra)")

    def _aws_vpc_endpoint(self, t, v, address):
        if (v.get("vpc_endpoint_type") or "Gateway") != "Interface":
            return Cost(0.0, "gateway endpoint (no charge)")
        azs = len(v.get("subnet_ids") or []) or 1
        return Cost(t["vpc_endpoint_hourly"] * HOURS * azs, f"interface endpoint in {azs} AZ (data is extra)")

    def _aws_cloudwatch_metric_alarm(self, t, v, address):
        queries = [q for q in (v.get("metric_query") or []) if q.get("metric")]
        n = len(queries) or 1
        period = (first(queries[0].get("metric")).get("period") if queries else v.get("period")) or 60
        kind = "high_resolution" if int(period) < 60 else "standard"
        return Cost(t["cloudwatch_alarm_month"][kind] * n, f"{n} metric{'s' if n > 1 else ''}, {kind.replace('_', ' ')}")

    def _aws_cloudwatch_composite_alarm(self, t, v, address):
        return Cost(t["cloudwatch_alarm_month"]["composite"], "composite alarm")

    def _aws_secretsmanager_secret(self, t, v, address):
        return Cost(t["secretsmanager_secret_month"], "secret (API calls are extra)")

    def _aws_kms_key(self, t, v, address):
        return Cost(t["kms_key_month"], "customer managed key (requests are extra)")

    _aws_kms_replica_key = _aws_kms_key

    def _aws_route53_zone(self, t, v, address):
        return Cost(t["route53_hosted_zone_month"], "hosted zone (queries are extra)")

    def _aws_dynamodb_table(self, t, v, address):
        if v.get("billing_mode") != "PROVISIONED":
            return None  # on-demand: billed by use
        r, w = int(v.get("read_capacity") or 0), int(v.get("write_capacity") or 0)
        cost = (r * t["dynamodb_rcu_hourly"] + w * t["dynamodb_wcu_hourly"]) * HOURS
        return Cost(cost, f"{r} RCU, {w} WCU provisioned (storage is extra)")


def action_name(actions: list[str]) -> str:
    if actions == ["no-op"] or actions == ["read"]:
        return "unchanged"
    if "delete" in actions and "create" in actions:
        return "replace"
    return {"create": "add", "delete": "remove", "update": "update"}.get(actions[0], actions[0])


def provider_region(plan: dict) -> str | None:
    cfg = plan.get("configuration", {}).get("provider_config", {}).get("aws", {})
    region = cfg.get("expressions", {}).get("region", {}).get("constant_value")
    return region if isinstance(region, str) else None


def analyze(plan: dict, prices_dir: Path, region: str | None, windows: set[str]) -> Report:
    region = region or provider_region(plan) or "us-west-2"
    report = Report(region=region)
    pricer = Pricer(prices_dir, region, windows)
    changes = [rc for rc in plan.get("resource_changes", []) if rc.get("mode") == "managed"]
    pricer.index_clusters(changes)
    for rc in changes:
        rtype, address = rc["type"], rc["address"]
        change = rc["change"]
        actions = change.get("actions", [])
        act = action_name(actions)
        before_v = None if actions == ["create"] else change.get("before")
        after_v = None if actions == ["delete"] else change.get("after")
        before = pricer.price(rtype, before_v, address) if isinstance(before_v, dict) else None
        after = pricer.price(rtype, after_v, address) if isinstance(after_v, dict) else None
        if before is None and after is None:
            if rtype in USAGE_BASED:
                if act != "unchanged":
                    report.usage.append(f"{address} ({act})")
            elif not rtype.startswith(FREE_PREFIXES) and act != "unchanged":
                report.uncovered[rtype] = report.uncovered.get(rtype, 0) + 1
            continue
        report.rows.append(Row(address, act, before, after))
    return report


def total(rows: list[Row], side: str) -> tuple[float, int]:
    s, unknown = 0.0, 0
    for r in rows:
        c = getattr(r, side)
        if c is None:
            continue
        if c.monthly is None:
            unknown += 1
        else:
            s += c.monthly
    return s, unknown


def render(report: Report, prices_dir: Path) -> str:
    out = [MARKER, f"### Monthly cost estimate ({report.region}, AWS list prices)", ""]
    before, bu = total(report.rows, "before")
    after, au = total(report.rows, "after")
    delta = after - before
    sign = "+" if delta >= 0 else "-"
    out.append(f"**{money(before)} → {money(after)} a month ({sign}{money(abs(delta))})** "
               "for the resources with a fixed price.")
    if bu or au:
        out.append(f"{max(bu, au)} resource(s) couldn't be priced from the plan and aren't in the totals (marked ?).")
    out.append("")
    changed = [r for r in report.rows if r.action != "unchanged"
               or (r.before and r.after and r.before.monthly != r.after.monthly)]
    if changed:
        out += ["| Resource | Change | Before | After | Basis |", "|---|---|---:|---:|---|"]
        for r in sorted(changed, key=lambda r: r.address):
            basis = (r.after or r.before).basis
            b = money(r.before.monthly) if r.before else "–"
            a = money(r.after.monthly) if r.after else "–"
            out.append(f"| `{r.address}` | {r.action} | {b} | {a} | {basis} |")
        out.append("")
    else:
        out += ["No change to any resource with a fixed price.", ""]
    if report.usage:
        out.append("<details><summary>Billed by use, not in the totals "
                   f"({len(report.usage)})</summary>\n")
        out += [f"- `{u}`" for u in sorted(report.usage)]
        out += ["", "</details>", ""]
    if report.uncovered:
        out.append("<details><summary>Changed resource types this check doesn't price yet "
                   f"({sum(report.uncovered.values())})</summary>\n")
        out += [f"- `{k}` × {n}" for k, n in sorted(report.uncovered.items())]
        out += ["", "</details>", ""]
    t = json.loads((prices_dir / f"{report.region}.json").read_text(encoding="utf-8")) \
        if (prices_dir / f"{report.region}.json").exists() else {}
    published = t.get("sources", {}).get("AmazonEC2", {}).get("publication_date", "unknown")
    out.append(f"<sub>On-demand list prices from the AWS Price List (EC2 file published {published}), "
               f"{HOURS} hours a month, EC2 priced as Linux. No free tier, Savings Plans, credits or tax. "
               "Built by PSD401/.github `scripts/iac/cost_diff.py` (standards/12-cloud-cost.md rule 12); "
               "it doesn't block the merge.</sub>")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plan", required=True, type=Path)
    ap.add_argument("--prices-dir", required=True, type=Path)
    ap.add_argument("--platform", default="aws")
    ap.add_argument("--region", help="default: the aws provider's region in the plan, else us-west-2")
    ap.add_argument("--windows", action="append", default=[], help="address of an EC2 instance that runs Windows")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    if args.platform != "aws":
        text = (f"{MARKER}\n### Monthly cost estimate\n\nNot available for `{args.platform}` yet: "
                "this check prices AWS plans only (standards/12-cloud-cost.md rule 12).\n")
    else:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        text = render(analyze(plan, args.prices_dir, args.region, set(args.windows)), args.prices_dir)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
