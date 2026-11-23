# ABOUTME: Tests for policy/redaction/redact-check.sh's aws-account-id pattern: a 12-digit run
# ABOUTME: inside a hex hash is clean, a bare or quoted 12-digit account ID is flagged.
"""Fixture values are built at run time so this file holds no 12-digit run
for the redaction check to find in it."""
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "policy/redaction/redact-check.sh"
ACCOUNT = "4071" + "3529" + "8164"  # not a real account; split so this source has no 12-digit run
# 64 hex chars whose 12-digit run sits between hex letters and at the end
HASH = "ab" + ACCOUNT + "cd" + "e" * 36 + ACCOUNT


def scan(tmp_path, text):
    f = tmp_path / "sample.txt"
    f.write_text(text + "\n")
    allow = tmp_path / "allow.txt"
    allow.write_text("")
    env = {"REDACT_ALLOW_FILE": str(allow), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    return subprocess.run(["bash", str(SCRIPT), "--paths", str(f)], env=env, capture_output=True, text=True)


def account_findings(result):
    return [ln for ln in result.stdout.splitlines() if ": aws-account-id: " in ln]


def test_hash_line_is_clean(tmp_path):
    assert len(HASH) == 64
    r = scan(tmp_path, f"    --hash=sha256:{HASH} \\")
    assert account_findings(r) == [], r.stdout


@pytest.mark.parametrize("line", [
    f'account_id = "{ACCOUNT}"',
    f"{ACCOUNT}",
    f"owner {ACCOUNT}",
    f"{ACCOUNT} is the account",
    f"arn:aws:iam::{ACCOUNT}:role/x",
])
def test_account_id_is_flagged_with_exactly_its_digits(tmp_path, line):
    r = scan(tmp_path, line)
    found = account_findings(r)
    assert found, r.stdout
    assert all(f.endswith(f": aws-account-id: {ACCOUNT}") for f in found), found
    assert r.returncode == 1


@pytest.mark.parametrize("line", [f"x{ACCOUNT}", f"{ACCOUNT}y", f"1{ACCOUNT}", f"v{ACCOUNT}0"])
def test_digits_glued_to_letters_or_digits_are_not_an_account(tmp_path, line):
    assert account_findings(scan(tmp_path, line)) == []


def test_diff_mode_flags_the_account_and_not_the_hash(tmp_path):
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "REDACT_ALLOW_FILE": str(tmp_path / "allow.txt")}
    (tmp_path / "allow.txt").write_text("")
    repo = tmp_path / "r"
    repo.mkdir()

    def git(*a):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t", *a],
                       cwd=repo, env=env, check=True, capture_output=True)
    git("init", "-q")
    (repo / "f.txt").write_text("start\n")
    git("add", "f.txt")
    git("commit", "-qm", "base")
    (repo / "f.txt").write_text(f"start\n--hash=sha256:{HASH}\naccount: {ACCOUNT}\n")
    git("commit", "-qam", "change")
    r = subprocess.run(["bash", str(SCRIPT), "--diff", "HEAD~1"], cwd=repo, env=env, capture_output=True, text=True)
    assert account_findings(r) == [f"REDACTION: f.txt:3: aws-account-id: {ACCOUNT}"], r.stdout


def scan_with_repo_allowlist(tmp_path, text):
    """Scan one line with the shipped policy/redaction/allow.txt (the default ALLOW_FILE)."""
    f = tmp_path / "sample.txt"
    f.write_text(text + "\n")
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    return subprocess.run(["bash", str(SCRIPT), "--paths", str(f)], env=env, capture_output=True, text=True)


# Values built at run time so this source holds no match for the scan to find.
SYSUPTIME_OID = ".".join(["1", "3", "6", "1", "2", "1", "1", "3", "0"])
LOOPBACK_NET = ".".join(["127", "0", "0", "0"]) + "/8"
DUMP_CHUNK = "zabbix" + "@" + "history.tsv.zst"


@pytest.mark.parametrize("line", [
    f'snmp_oid: "{SYSUPTIME_OID}"',
    f"view systemonly included .{SYSUPTIME_OID}",
    f"mynetworks = {LOOPBACK_NET} 192.0.2.10/32",
    f'echo rows > "$target/{DUMP_CHUNK}"',
])
def test_repo_allowlist_clears_known_false_positives(tmp_path, line):
    r = scan_with_repo_allowlist(tmp_path, line)
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("line", [
    ".".join(["10", "2", "1", "1", "3"]),        # 2.1.1.3 inside a longer dotted run is still flagged as 10.2.1.1
    ".".join(["2", "1", "1", "30"]),             # a near neighbour of the allowed fragment
    ".".join(["1", "3", "6", "10"]),
    ".".join(["127", "0", "0", "0"]) + "/16",    # only the /8 loopback block is allowed
    "zabbix" + "@" + "history.example.org",      # a real-shaped address with a chunk-like local part
    "ops" + "@" + "history.tsv.zst.example.org",
])
def test_repo_allowlist_entries_stay_narrow(tmp_path, line):
    r = scan_with_repo_allowlist(tmp_path, line)
    assert r.returncode == 1, r.stdout
