# ABOUTME: Tests for cost_diff.py: prices a plan fixture against a fixture price table and checks
# ABOUTME: each total, the usage-based and not-priced lists, and the non-AWS message.
"""standards/12-cloud-cost.md rule 12. Plan: fixtures/cost_diff/plan.json, shaped like
`terraform show -json`. Prices: fixtures/cost_diff/prices-us-west-2.json, a cut of
prices/aws/us-west-2.json (AWS Price List, published 2026-11-24)."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
SCRIPT = HERE / "cost_diff.py"
FIX = HERE / "fixtures" / "cost_diff"
sys.path.insert(0, str(HERE))
import cost_diff  # noqa: E402


@pytest.fixture
def prices(tmp_path):
    d = tmp_path / "prices"
    d.mkdir()
    shutil.copy(FIX / "prices-us-west-2.json", d / "us-west-2.json")
    return d


def plan():
    return json.loads((FIX / "plan.json").read_text())


def row(report, address):
    return next(r for r in report.rows if r.address == address)


def test_each_priced_resource(prices):
    rep = cost_diff.analyze(plan(), prices, None, set())
    assert rep.region == "us-west-2"
    # 0.0168/h x 730 + 20 GB gp3 at 0.08 (3000 IOPS and 125 MiB/s are included)
    assert row(rep, "aws_instance.web").after.monthly == pytest.approx(12.264 + 1.6)
    db = row(rep, "aws_db_instance.app")
    assert db.before.monthly == pytest.approx(0.016 * 730 + 20 * 0.115)
    assert db.after.monthly == pytest.approx(0.032 * 730 + 20 * 0.23)
    # Serverless v2 floor: the cluster's 0.5 ACU minimum at 0.12 per ACU-hour
    assert row(rep, "aws_rds_cluster_instance.db[0]").after.monthly == pytest.approx(0.5 * 0.12 * 730)
    nat = row(rep, "aws_nat_gateway.old")
    assert nat.action == "remove" and nat.after is None and nat.before.monthly == pytest.approx(32.85)
    assert row(rep, "aws_secretsmanager_secret.db").after.monthly == 0.40
    assert row(rep, "aws_cloudwatch_metric_alarm.errors").action == "unchanged"


def test_totals_and_lists(prices):
    rep = cost_diff.analyze(plan(), prices, None, set())
    assert cost_diff.total(rep.rows, "before") == (pytest.approx(46.93), 0)
    assert cost_diff.total(rep.rows, "after") == (pytest.approx(86.124), 0)
    assert rep.usage == ["aws_lambda_function.api (add)"]
    assert rep.uncovered == {"aws_opensearch_domain": 1}  # aws_iam_role is free, data sources skipped


def test_rendered_comment(prices, tmp_path):
    out = tmp_path / "cost.md"
    r = subprocess.run([sys.executable, str(SCRIPT), "--plan", str(FIX / "plan.json"),
                        "--prices-dir", str(prices), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert text.startswith(cost_diff.MARKER)
    assert "**$46.93 → $86.12 a month (+$39.19)**" in text
    assert "| `aws_nat_gateway.old` | remove | $32.85 | – |" in text
    assert "aws_cloudwatch_metric_alarm.errors" not in text  # unchanged and same price: not listed
    assert "published 2026-11-24T23:14:17Z" in text


def test_windows_instance(prices):
    p = plan()
    p["resource_changes"][0]["change"]["after"]["instance_type"] = "t3.medium"
    rep = cost_diff.analyze(p, prices, None, {"aws_instance.web"})
    assert row(rep, "aws_instance.web").after.monthly == pytest.approx(0.06 * 730 + 1.6)


def test_unknown_instance_type_is_unpriced_not_zero(prices):
    p = plan()
    p["resource_changes"][0]["change"]["after"]["instance_type"] = "z9.huge"
    rep = cost_diff.analyze(p, prices, None, set())
    web = row(rep, "aws_instance.web")
    assert web.after.monthly is None and web.after.basis == "not in the price list"
    assert cost_diff.total(rep.rows, "after")[1] == 1


def test_gp3_extra_iops_and_throughput(prices):
    t = json.loads((prices / "us-west-2.json").read_text())
    p = cost_diff.Pricer(prices, "us-west-2", set())
    cost, _ = p._ebs(t, "gp3", 100, iops=6000, throughput=250)
    assert cost == pytest.approx(100 * 0.08 + 3000 * 0.005 + 125 * 0.04)


def test_alarm_metric_math_counts_each_metric(prices):
    p = cost_diff.Pricer(prices, "us-west-2", set())
    alarm = {"metric_query": [{"metric": [{"period": 60}]}, {"metric": [{"period": 60}]}, {"expression": "m1/m2"}]}
    assert p.price("aws_cloudwatch_metric_alarm", alarm, "a").monthly == pytest.approx(0.2)


def test_other_region_without_a_table(prices):
    rep = cost_diff.analyze(plan(), prices, "eu-west-1", set())
    assert row(rep, "aws_instance.web").after.basis == "no price table for eu-west-1"


def test_gcp_is_reported_not_priced(prices, tmp_path):
    out = tmp_path / "cost.md"
    r = subprocess.run([sys.executable, str(SCRIPT), "--plan", str(FIX / "plan.json"), "--prices-dir",
                        str(prices), "--platform", "gcp", "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0
    assert "Not available for `gcp` yet" in out.read_text()


def test_committed_tables_load_and_cover_the_fixture_types():
    """prices/aws/*.json are what callers get; every key the pricer reads must be there."""
    tables = sorted((HERE.parents[1] / "prices" / "aws").glob("*.json"))
    assert {t.stem for t in tables} >= {"us-west-2", "us-east-1"}
    for path in tables:
        t = json.loads(path.read_text())
        assert t["region"] == path.stem
        assert t["ec2_instance_hourly"]["Linux"]["t4g.small"] > 0
        assert t["rds_instance_hourly"]["PostgreSQL"]["Single-AZ"]["db.t4g.micro"] > 0
        assert t["aurora_serverless_v2_acu_hourly"]["Aurora PostgreSQL"]["standard"] > 0
        assert t["sources"]["AmazonEC2"]["publication_date"]
