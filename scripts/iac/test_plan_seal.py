# ABOUTME: Tests for plan_seal.py, which age-encrypts the binary Terraform plan for
# ABOUTME: the apply job and decrypts it there with the environment's secret key.
"""Runs the real age binary. Skips when age is not on PATH, unless
REQUIRE_AGE=1 (CI sets it after scripts/iac/install_age.sh), so CI cannot
pass by skipping."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("plan_seal.py")
SENTINEL = b"SENTINEL_hunter2 plaintext plan bytes"

if shutil.which("age") is None or shutil.which("age-keygen") is None:
    if os.environ.get("REQUIRE_AGE") == "1":
        raise RuntimeError("REQUIRE_AGE=1 but age/age-keygen are not on PATH")
    pytest.skip("age not on PATH (scripts/iac/install_age.sh installs it)", allow_module_level=True)


def keypair():
    out = subprocess.run(["age-keygen"], check=True, capture_output=True, text=True).stdout
    secret = next(l for l in out.splitlines() if l.startswith("AGE-SECRET-KEY-"))
    public = subprocess.run(["age-keygen", "-y"], input=secret + "\n", check=True,
                            capture_output=True, text=True).stdout.strip()
    return public, secret


def run(args, env=None, cwd=None):
    full_env = {k: v for k, v in os.environ.items() if k != "PSD_PLAN_KEY"}
    full_env.update(env or {})
    return subprocess.run([sys.executable, str(SCRIPT), *args], env=full_env, cwd=cwd,
                          capture_output=True, text=True)


def test_seal_then_open_round_trips_and_removes_plaintext(tmp_path):
    public, secret = keypair()
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    r = run(["seal", "--recipient", public, str(plan), str(tmp_path / "tfplan.age")])
    assert r.returncode == 0, r.stderr
    assert not plan.exists()
    sealed = (tmp_path / "tfplan.age").read_bytes()
    assert SENTINEL not in sealed
    r = run(["open", str(tmp_path / "tfplan.age"), str(plan)], env={"PSD_PLAN_KEY": secret})
    assert r.returncode == 0, r.stderr
    assert plan.read_bytes() == SENTINEL


def test_seal_refuses_a_secret_key_as_recipient_without_echoing_it(tmp_path):
    _, secret = keypair()
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    r = run(["seal", "--recipient", secret, str(plan), str(tmp_path / "tfplan.age")])
    assert r.returncode != 0
    assert "secret key" in r.stderr
    assert secret not in r.stderr + r.stdout
    assert not (tmp_path / "tfplan.age").exists()


@pytest.mark.parametrize("recipient", ["", "ssh-ed25519 AAAAC3Nza", "age1short"])
def test_seal_refuses_a_malformed_recipient(tmp_path, recipient):
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    r = run(["seal", "--recipient", recipient, str(plan), str(tmp_path / "tfplan.age")])
    assert r.returncode != 0
    assert "PSD_PLAN_RECIPIENT" in r.stderr or "plan_recipient" in r.stderr
    assert not (tmp_path / "tfplan.age").exists()


def test_open_without_the_key_names_the_secret_to_set(tmp_path):
    public, _ = keypair()
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    run(["seal", "--recipient", public, str(plan), str(tmp_path / "tfplan.age")])
    r = run(["open", str(tmp_path / "tfplan.age"), str(plan)], env={"PSD_PLAN_KEY": ""})
    assert r.returncode != 0
    assert "PSD_PLAN_KEY" in r.stderr
    assert not plan.exists()


def test_open_with_the_wrong_key_fails_and_leaves_no_output(tmp_path):
    public, _ = keypair()
    _, other_secret = keypair()
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    run(["seal", "--recipient", public, str(plan), str(tmp_path / "tfplan.age")])
    r = run(["open", str(tmp_path / "tfplan.age"), str(plan)], env={"PSD_PLAN_KEY": other_secret})
    assert r.returncode != 0
    assert not plan.exists()
    assert other_secret not in r.stderr + r.stdout


def test_open_leaves_no_identity_file_behind(tmp_path):
    public, secret = keypair()
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    plan = tmp_path / "tfplan"
    plan.write_bytes(SENTINEL)
    run(["seal", "--recipient", public, str(plan), str(tmp_path / "tfplan.age")])
    r = run(["open", str(tmp_path / "tfplan.age"), str(plan)],
            env={"PSD_PLAN_KEY": secret, "TMPDIR": str(scratch)})
    assert r.returncode == 0, r.stderr
    assert list(scratch.iterdir()) == []
