#!/usr/bin/env python3
# ABOUTME: Builds prices/aws/<region>.json, the list prices cost_diff.py reads, from AWS's public
# ABOUTME: Price List bulk files. No account, key or service: the files are public.
"""Build the AWS price tables that cost_diff.py prices Terraform plans with.

Usage:
  build_price_table.py --out-dir prices/aws [--region us-west-2 ...] [--csv-dir DIR]

Source: the AWS Price List Bulk API, one public CSV per service and Region,
https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<offer>/current/<region>/index.csv
(Route 53 is global: .../AmazonRoute53/current/index.csv). No credentials are
needed. The EC2 file is about 300 MB, so every file is streamed row by row
with the standard library and never held in memory.

--csv-dir reads <offer>.csv (and <offer>-<region>.csv) from a folder instead of
downloading: the tests use it, and so can a person checking a table by hand.

Only on-demand list prices are kept, and only the rows cost_diff.py uses
(standards/12-cloud-cost.md rule 12). PSD's reseller bills at list price, so
list price is what PSD pays before credits.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import tempfile
import urllib.request
from pathlib import Path

BULK = "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws"
# 13-aws-accounts.md rule 6: us-west-2 by default, us-east-1 for Bedrock-heavy apps.
DEFAULT_REGIONS = ["us-west-2", "us-east-1"]
REGIONAL_OFFERS = [
    "AmazonEC2", "AmazonRDS", "AWSELB", "AmazonVPC", "AmazonCloudWatch",
    "AWSSecretsManager", "awskms", "AmazonDynamoDB",
]
GLOBAL_OFFERS = ["AmazonRoute53"]
# Engines PSD runs (23-database-access.md): PostgreSQL first, MySQL and MariaDB
# for vendor apps. Licensed engines (Oracle, SQL Server, Db2) are left out.
RDS_ENGINES = {"PostgreSQL", "MySQL", "MariaDB", "Aurora PostgreSQL", "Aurora MySQL"}
# operation code -> the name cost_diff.py uses. Linux is RunInstances with no
# suffix; Windows with a license included is RunInstances:0002.
EC2_OS = {"RunInstances": "Linux", "RunInstances:0002": "Windows"}
METADATA_ROWS = 5  # FormatVersion, Disclaimer, Publication Date, Version, OfferCode


def strip_usage_prefix(usage_type: str, region: str) -> str:
    """'USW2-BoxUsage:t4g.small' -> 'BoxUsage:t4g.small'. us-east-1 rows often
    have no prefix; KMS uses the Region code itself ('us-west-2-KMS-Keys')."""
    for prefix in (f"{region}-",):
        if usage_type.startswith(prefix):
            return usage_type[len(prefix):]
    m = re.match(r"^[A-Z]{3}\d-", usage_type)  # USW2-, USE1-, APN1- ...
    return usage_type[m.end():] if m else usage_type


def open_offer(offer: str, region: str | None, csv_dir: Path | None):
    """Return (metadata dict, csv.DictReader) for one offer file."""
    if csv_dir is not None:
        name = f"{offer}-{region}.csv" if region and (csv_dir / f"{offer}-{region}.csv").exists() else f"{offer}.csv"
        fh = open(csv_dir / name, newline="", encoding="utf-8")
        url = str(csv_dir / name)
    else:
        url = f"{BULK}/{offer}/current/{region}/index.csv" if region else f"{BULK}/{offer}/current/index.csv"
        tmp = tempfile.TemporaryFile(mode="w+b")
        with urllib.request.urlopen(url, timeout=600) as resp:  # noqa: S310 (fixed https URL)
            while chunk := resp.read(1 << 20):
                tmp.write(chunk)
        tmp.seek(0)
        fh = io.TextIOWrapper(tmp, encoding="utf-8", newline="")
    meta = {}
    for _ in range(METADATA_ROWS):
        row = next(csv.reader([fh.readline()]))
        meta[row[0]] = row[1]
    source = {
        "url": url if csv_dir is None else f"{offer} (local file)",
        "publication_date": meta.get("Publication Date", ""),
        "version": meta.get("Version", ""),
    }
    return fh, source, csv.DictReader(fh)


def price(row) -> float:
    return float(row["PricePerUnit"])


def put(table: dict, keys: list[str], value: float, conflicts: list[str]) -> None:
    """Set table[k1][k2]...=value; record a conflict if a different value is already there."""
    node = table
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    old = node.get(keys[-1])
    if old is not None and old != value:
        conflicts.append(f"{'/'.join(keys)}: {old} vs {value}")
        value = max(old, value)  # never under-estimate
    node[keys[-1]] = value


def build_region(region: str, csv_dir: Path | None) -> dict:
    t: dict = {"region": region, "currency": "USD", "sources": {}}
    conflicts: list[str] = []

    def rows(offer: str, scope: str | None):
        fh, source, reader = open_offer(offer, scope, csv_dir)
        t["sources"][offer] = source
        with fh:
            for row in reader:
                if row.get("TermType") != "OnDemand" or row.get("Currency") != "USD":
                    continue
                if scope and row.get("Region Code") not in (region, ""):
                    continue
                yield row, strip_usage_prefix(row.get("usageType", ""), region)

    for row, usage in rows("AmazonEC2", region):
        family = row.get("Product Family", "")
        if (usage.startswith("BoxUsage:") and row.get("Tenancy") == "Shared"
                and row.get("CapacityStatus") == "Used" and row.get("Pre Installed S/W") == "NA"
                and row.get("operation") in EC2_OS):
            put(t, ["ec2_instance_hourly", EC2_OS[row["operation"]], row["Instance Type"]], price(row), conflicts)
        elif family == "Storage" and usage.startswith("EBS:VolumeUsage") and row.get("Volume API Name"):
            put(t, ["ebs_gb_month", row["Volume API Name"]], price(row), conflicts)
        elif family == "System Operation" and re.fullmatch(r"EBS:VolumeP-IOPS\.(gp3|piops|io2)", usage):
            put(t, ["ebs_iops_month", row["Volume API Name"]], price(row), conflicts)
        elif family == "Provisioned Throughput" and usage == "EBS:VolumeP-Throughput.gp3":
            # Listed per GiBps-month; gp3 throughput is set in MiB/s.
            put(t, ["ebs_gp3_throughput_mibps_month"], round(price(row) / 1024, 10), conflicts)
        elif usage == "NatGateway-Hours":
            put(t, ["nat_gateway_hourly"], price(row), conflicts)

    for row, usage in rows("AmazonRDS", region):
        engine = row.get("Database Engine", "")
        if engine not in RDS_ENGINES or row.get("License Model") not in ("No license required", ""):
            continue
        deployment = row.get("Deployment Option", "")
        if re.fullmatch(r"(InstanceUsage|Multi-AZUsage):db\.[\w.]+", usage) and deployment in ("Single-AZ", "Multi-AZ"):
            put(t, ["rds_instance_hourly", engine, deployment, row["Instance Type"]], price(row), conflicts)
        elif usage == "Aurora:ServerlessV2Usage":
            put(t, ["aurora_serverless_v2_acu_hourly", engine, "standard"], price(row), conflicts)
        elif usage == "Aurora:ServerlessV2IOOptimizedUsage":
            put(t, ["aurora_serverless_v2_acu_hourly", engine, "io_optimized"], price(row), conflicts)
        elif (row.get("Product Family") == "Database Storage" and deployment in ("Single-AZ", "Multi-AZ")
              and not engine.startswith("Aurora")):
            vol = {"General Purpose": "gp2", "General Purpose-GP3": "gp3", "Provisioned IOPS": "io1",
                   "Provisioned IOPS-IO2": "io2", "Magnetic": "standard"}.get(row.get("Volume Type", ""))
            if vol:
                put(t, ["rds_storage_gb_month", engine, deployment, vol], price(row), conflicts)

    for row, usage in rows("AWSELB", region):
        kind = {"Load Balancer-Application": "application", "Load Balancer-Network": "network",
                "Load Balancer-Gateway": "gateway"}.get(row.get("Product Family", ""))
        if kind and usage == "LoadBalancerUsage":
            put(t, ["elb_hourly", kind], price(row), conflicts)

    for row, usage in rows("AmazonVPC", region):
        if usage == "PublicIPv4:InUseAddress":
            put(t, ["public_ipv4_hourly"], price(row), conflicts)
        elif usage == "VpcEndpoint-Hours":
            put(t, ["vpc_endpoint_hourly"], price(row), conflicts)

    for row, usage in rows("AmazonCloudWatch", region):
        kind = {"CW:AlarmMonitorUsage": "standard", "CW:HighResAlarmMonitorUsage": "high_resolution",
                "CW:CompositeAlarmMonitorUsage": "composite"}.get(usage)
        if kind and price(row) > 0:
            put(t, ["cloudwatch_alarm_month", kind], price(row), conflicts)

    for row, _ in rows("AWSSecretsManager", region):
        if row.get("Unit") == "Secrets":
            put(t, ["secretsmanager_secret_month"], price(row), conflicts)

    for row, usage in rows("awskms", region):
        if usage == "KMS-Keys":
            put(t, ["kms_key_month"], price(row), conflicts)

    for row, usage in rows("AmazonDynamoDB", region):
        # Provisioned capacity beyond the free tier (StartingRange > 0); not reserved.
        if usage in ("ReadCapacityUnit-Hrs", "WriteCapacityUnit-Hrs") and row.get("StartingRange") not in ("0", ""):
            put(t, ["dynamodb_rcu_hourly" if usage.startswith("Read") else "dynamodb_wcu_hourly"], price(row), conflicts)

    for row, usage in rows("AmazonRoute53", None):
        if usage == "HostedZone" and row.get("StartingRange") == "0":
            put(t, ["route53_hosted_zone_month"], price(row), conflicts)

    required = ["ec2_instance_hourly", "ebs_gb_month", "nat_gateway_hourly", "rds_instance_hourly",
                "aurora_serverless_v2_acu_hourly", "elb_hourly", "public_ipv4_hourly", "vpc_endpoint_hourly",
                "cloudwatch_alarm_month", "secretsmanager_secret_month", "kms_key_month",
                "route53_hosted_zone_month"]
    missing = [k for k in required if k not in t]
    if missing:
        raise SystemExit(f"{region}: no rows found for {', '.join(missing)}; the price list format may have changed")
    if conflicts:
        t["conflicts_kept_higher"] = sorted(conflicts)
    return t


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--region", action="append", dest="regions")
    ap.add_argument("--csv-dir", type=Path)
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for region in args.regions or DEFAULT_REGIONS:
        table = build_region(region, args.csv_dir)
        out = args.out_dir / f"{region}.json"
        out.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
