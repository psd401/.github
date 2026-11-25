# ABOUTME: Tests for build_price_table.py against small CSVs in the AWS Price List bulk format:
# ABOUTME: which rows are kept, region prefixes stripped, and a missing section fails the build.
"""The CSV layout (five metadata rows, then a header) is the one AWS publishes at
https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<offer>/current/<region>/index.csv,
read 2026-11-25. Rows here are copied from those files, cut to the columns the builder reads."""
import csv
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import build_price_table as b  # noqa: E402

COLS = ["TermType", "Currency", "Region Code", "usageType", "operation", "Unit", "PricePerUnit",
        "StartingRange", "Product Family", "Instance Type", "Tenancy", "CapacityStatus", "Pre Installed S/W",
        "Volume API Name", "Database Engine", "Deployment Option", "License Model", "Volume Type"]


def od(region, usage, price, **kw):
    r = {"TermType": "OnDemand", "Currency": "USD", "Region Code": region, "usageType": usage,
         "PricePerUnit": str(price)}
    r.update({k.replace("_", " ").replace("S W", "S/W"): v for k, v in kw.items()})
    return r


def write(dirpath: Path, name: str, rows: list[dict], published="2026-11-24T23:14:17Z"):
    with open(dirpath / name, "w", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL)
        for k, v in [("FormatVersion", "v1.0"), ("Disclaimer", "x"), ("Publication Date", published),
                     ("Version", "20261124231417"), ("OfferCode", name.split(".")[0].split("-")[0])]:
            w.writerow([k, v])
        dw = csv.DictWriter(fh, fieldnames=COLS, quoting=csv.QUOTE_ALL, extrasaction="ignore")
        dw.writeheader()
        for row in rows:
            dw.writerow(row)


def fixture_dir(tmp_path, region="us-west-2", pfx="USW2-"):
    d = tmp_path / "csv"
    d.mkdir()
    ec2 = [
        od(region, f"{pfx}BoxUsage:t4g.small", 0.0168, operation="RunInstances", Instance_Type="t4g.small",
           Tenancy="Shared", CapacityStatus="Used", Pre_Installed_S_W="NA"),
        od(region, f"{pfx}BoxUsage:t4g.small", 0.0456, operation="RunInstances:0010", Instance_Type="t4g.small",
           Tenancy="Shared", CapacityStatus="Used", Pre_Installed_S_W="NA"),  # RHEL: dropped
        od(region, f"{pfx}UnusedBox:t4g.small", 0.0168, operation="RunInstances", Instance_Type="t4g.small",
           Tenancy="Shared", CapacityStatus="UnusedCapacityReservation", Pre_Installed_S_W="NA"),
        od(region, f"{pfx}BoxUsage:t3.medium", 0.06, operation="RunInstances:0002", Instance_Type="t3.medium",
           Tenancy="Shared", CapacityStatus="Used", Pre_Installed_S_W="NA"),
        od(region, f"{pfx}EBS:VolumeUsage.gp3", 0.08, Product_Family="Storage", Volume_API_Name="gp3"),
        od(region, f"{pfx}EBS:VolumeP-IOPS.gp3", 0.005, Product_Family="System Operation", Volume_API_Name="gp3"),
        od(region, f"{pfx}EBS:VolumeP-Throughput.gp3", 40.96, Product_Family="Provisioned Throughput"),
        od(region, f"{pfx}NatGateway-Hours", 0.045, Product_Family="NAT Gateway"),
        {**od(region, f"{pfx}NatGateway-Hours", 0.03), "TermType": "Reserved"},  # not on-demand: dropped
    ]
    # The real license column for these engines is "No license required"; the
    # Serverless v2 rows leave it empty, which the builder must accept.
    rds = [
        od(region, f"{pfx}InstanceUsage:db.t4g.micro", 0.016, Instance_Type="db.t4g.micro", Database_Engine="PostgreSQL",
           Deployment_Option="Single-AZ", License_Model="No license required"),
        od(region, f"{pfx}Multi-AZUsage:db.t4g.micro", 0.032, Instance_Type="db.t4g.micro",
           Database_Engine="PostgreSQL", Deployment_Option="Multi-AZ", License_Model="No license required"),
        od(region, f"{pfx}InstanceUsage:db.t4g.micro", 0.9, Instance_Type="db.t4g.micro", Database_Engine="Oracle",
           Deployment_Option="Single-AZ", License_Model="License included"),  # dropped
        od(region, f"{pfx}Aurora:ServerlessV2Usage", 0.12, Database_Engine="Aurora PostgreSQL"),
        od(region, f"{pfx}RDS:GP3-Storage", 0.115, Product_Family="Database Storage", Database_Engine="PostgreSQL",
           Deployment_Option="Single-AZ", Volume_Type="General Purpose-GP3"),
    ]
    write(d, "AmazonEC2.csv", ec2)
    write(d, "AmazonRDS.csv", rds)
    write(d, "AWSELB.csv", [od(region, f"{pfx}LoadBalancerUsage", 0.0225, Product_Family="Load Balancer-Application"),
                            od(region, f"{pfx}TS-LoadBalancerUsage", 0.0063,
                               Product_Family="Load Balancer-Application")])
    write(d, "AmazonVPC.csv", [od(region, f"{pfx}PublicIPv4:InUseAddress", 0.005),
                               od(region, f"{pfx}VpcEndpoint-Hours", 0.01)])
    write(d, "AmazonCloudWatch.csv", [od(region, f"{pfx}CW:AlarmMonitorUsage", 0.1),
                                      od("", "Global-CW:AlarmMonitorUsage", 0)])
    write(d, "AWSSecretsManager.csv", [od(region, f"{pfx}AWSSecretsManager-Secrets", 0.4, Unit="Secrets")])
    write(d, "awskms.csv", [od(region, f"{region}-KMS-Keys", 1.0, Unit="Keys")])
    write(d, "AmazonDynamoDB.csv", [od(region, f"{pfx}ReadCapacityUnit-Hrs", 0, StartingRange="0"),
                                    od(region, f"{pfx}ReadCapacityUnit-Hrs", 0.00013, StartingRange="18600")])
    write(d, "AmazonRoute53.csv", [od("", "HostedZone", 0.5, StartingRange="0"),
                                   od("", "HostedZone", 0.1, StartingRange="25")])
    return d


def test_builds_expected_table(tmp_path):
    t = b.build_region("us-west-2", fixture_dir(tmp_path))
    assert t["ec2_instance_hourly"] == {"Linux": {"t4g.small": 0.0168}, "Windows": {"t3.medium": 0.06}}
    assert t["ebs_gb_month"] == {"gp3": 0.08}
    assert t["ebs_gp3_throughput_mibps_month"] == pytest.approx(0.04)
    assert t["nat_gateway_hourly"] == 0.045
    assert t["rds_instance_hourly"] == {"PostgreSQL": {"Single-AZ": {"db.t4g.micro": 0.016},
                                                       "Multi-AZ": {"db.t4g.micro": 0.032}}}
    assert t["aurora_serverless_v2_acu_hourly"] == {"Aurora PostgreSQL": {"standard": 0.12}}
    assert t["rds_storage_gb_month"] == {"PostgreSQL": {"Single-AZ": {"gp3": 0.115}}}
    assert t["elb_hourly"] == {"application": 0.0225}  # the TS- (trust store) row is not the LB hour
    assert t["cloudwatch_alarm_month"] == {"standard": 0.1}
    assert t["kms_key_month"] == 1.0 and t["secretsmanager_secret_month"] == 0.4
    assert t["dynamodb_rcu_hourly"] == 0.00013  # free-tier row skipped
    assert t["route53_hosted_zone_month"] == 0.5
    assert t["sources"]["AmazonEC2"]["publication_date"] == "2026-11-24T23:14:17Z"
    assert "conflicts_kept_higher" not in t


def test_us_east_1_rows_without_a_prefix(tmp_path):
    t = b.build_region("us-east-1", fixture_dir(tmp_path, region="us-east-1", pfx=""))
    assert t["ec2_instance_hourly"]["Linux"]["t4g.small"] == 0.0168
    assert t["kms_key_month"] == 1.0


def test_missing_section_fails(tmp_path):
    d = fixture_dir(tmp_path)
    write(d, "AmazonVPC.csv", [])
    with pytest.raises(SystemExit, match="public_ipv4_hourly"):
        b.build_region("us-west-2", d)


def test_conflicting_rows_keep_the_higher_price():
    t, conflicts = {}, []
    b.put(t, ["nat_gateway_hourly"], 0.045, conflicts)
    b.put(t, ["nat_gateway_hourly"], 0.05, conflicts)
    assert t["nat_gateway_hourly"] == 0.05 and conflicts == ["nat_gateway_hourly: 0.045 vs 0.05"]


def test_main_writes_sorted_json(tmp_path):
    d = fixture_dir(tmp_path)
    out = tmp_path / "out"
    assert b.main(["--out-dir", str(out), "--region", "us-west-2", "--csv-dir", str(d)]) == 0
    text = (out / "us-west-2.json").read_text()
    assert json.loads(text)["region"] == "us-west-2"
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True) + "\n"


@pytest.mark.parametrize("usage,expected", [
    ("USW2-BoxUsage:t4g.small", "BoxUsage:t4g.small"),
    ("BoxUsage:t4g.small", "BoxUsage:t4g.small"),
    ("us-west-2-KMS-Keys", "KMS-Keys"),
    ("USW2-TS-LoadBalancerUsage", "TS-LoadBalancerUsage"),
])
def test_strip_usage_prefix(usage, expected):
    assert b.strip_usage_prefix(usage, "us-west-2") == expected
