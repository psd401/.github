# ABOUTME: Tests for install_age.sh: it installs age only from a tarball whose SHA-256
# ABOUTME: matches the pin, and installs nothing when the hash does not match.
"""Offline. AGE_BASE_URL points the script at a local file:// directory."""
import subprocess
import tarfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("install_age.sh")


def fake_release(tmp_path):
    rel = tmp_path / "release"
    rel.mkdir()
    src = tmp_path / "age"
    src.mkdir()
    for name in ("age", "age-keygen"):
        (src / name).write_text("#!/bin/sh\necho tampered\n")
    for asset in ("age-v1.3.2-linux-amd64.tar.gz", "age-v1.3.2-darwin-arm64.tar.gz"):
        with tarfile.open(rel / asset, "w:gz") as t:
            t.add(src, arcname="age")
    return rel


def test_tarball_with_the_wrong_hash_is_refused_and_nothing_is_installed(tmp_path):
    rel = fake_release(tmp_path)
    dest = tmp_path / "bin"
    gh_path = tmp_path / "github_path"
    r = subprocess.run(["bash", str(SCRIPT), str(dest)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "AGE_BASE_URL": rel.as_uri(),
                            "GITHUB_PATH": str(gh_path), "RUNNER_TEMP": str(tmp_path)})
    assert r.returncode != 0
    assert "SHA-256" in r.stderr
    assert not (dest / "age").exists()
    assert not gh_path.exists() or gh_path.read_text() == ""
