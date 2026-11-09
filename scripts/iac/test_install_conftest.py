# ABOUTME: Tests for install_conftest.sh: it installs conftest only from a tarball whose
# ABOUTME: SHA-256 matches the pin, and installs nothing when the hash does not match.
"""Offline. CONFTEST_BASE_URL points the script at a local file:// directory."""
import subprocess
import tarfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("install_conftest.sh")


def fake_release(tmp_path):
    rel = tmp_path / "release"
    rel.mkdir()
    binary = tmp_path / "conftest"
    binary.write_text("#!/bin/sh\necho tampered\n")
    for asset in ("conftest_0.71.0_Linux_x86_64.tar.gz", "conftest_0.71.0_Darwin_arm64.tar.gz"):
        with tarfile.open(rel / asset, "w:gz") as t:
            t.add(binary, arcname="conftest")
    return rel


def test_tarball_with_the_wrong_hash_is_refused_and_nothing_is_installed(tmp_path):
    rel = fake_release(tmp_path)
    dest = tmp_path / "bin"
    gh_path = tmp_path / "github_path"
    r = subprocess.run(["bash", str(SCRIPT), str(dest)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "CONFTEST_BASE_URL": rel.as_uri(),
                            "GITHUB_PATH": str(gh_path), "RUNNER_TEMP": str(tmp_path)})
    assert r.returncode != 0
    assert "SHA-256" in r.stderr
    assert not (dest / "conftest").exists()
    assert not gh_path.exists() or gh_path.read_text() == ""


REUSABLES = [Path(__file__).resolve().parents[2] / ".github/workflows" / name
             for name in ("reusable-iac-checks.yml", "reusable-onprem-checks.yml")]


def test_reusables_install_conftest_only_through_the_pinned_script():
    """The conftest job evaluates the policy denies (student-pii log rules
    included), so a substituted binary that reports no denials would pass a
    plan through it."""
    import yaml
    for wf in REUSABLES:
        for job_name, job in yaml.safe_load(wf.read_text())["jobs"].items():
            runs = [s.get("run") or "" for s in job.get("steps") or []]
            if not any("conftest test" in r or "conftest verify" in r for r in runs):
                continue
            assert not any("open-policy-agent/conftest/releases" in r for r in runs), \
                f"{wf.name} {job_name} downloads conftest without the SHA-256 check"
            assert any("_policy/scripts/iac/install_conftest.sh" in r for r in runs), \
                f"{wf.name} {job_name} runs conftest without install_conftest.sh"
