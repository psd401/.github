# ABOUTME: Offline tests for docs_boundary.py, run on temporary git repos.
# ABOUTME: Run: python3 -I scripts/test_docs_boundary.py (CI: docs-boundary-test.yml).
"""Tests for docs_boundary.py: what is found, what fails a pull request, and
that no output line carries a matched value."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("docs_boundary", HERE / "docs_boundary.py")
db = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db)

ADDR = "10.20.30.40"
MAC = "00:1a:2b:3c:4d:5e"


def sh(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


class Repo:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        sh(self.path, "init", "-q", "-b", "main")
        sh(self.path, "config", "user.email", "t@example.invalid")
        sh(self.path, "config", "user.name", "t")

    def write(self, rel: str, text: str) -> None:
        f = self.path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def commit(self) -> str:
        sh(self.path, "add", "-A")
        sh(self.path, "commit", "-q", "-m", "c")
        return sh(self.path, "rev-parse", "HEAD").strip()

    def run(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = db.main([str(self.path), *args])
        return code, out.getvalue()


class Findings(unittest.TestCase):
    def kinds(self, repo: Repo, *domains: str) -> list[tuple[str, int, str]]:
        return db.findings(repo.path, list(domains))

    def test_private_addresses_and_macs_outside_restricted(self) -> None:
        r = Repo()
        r.write("README.md", f"core is {ADDR}\n")
        r.write("tests/fixture.py", f'MAC = "{MAC}"\nV6 = "fd12:3456::1"\nDOT = "001a.2b3c.4d5e"\n')
        r.write("docs/restricted/hosts.md", f"{ADDR}\n")
        r.write(".openwikiignore", "docs/restricted/\n")
        r.write("ok.md", "doc range 192.0.2.10, public 8.8.8.8, version 10.2.3\n")
        r.commit()
        self.assertEqual(sorted(self.kinds(r)), [
            ("README.md", 1, "restricted"),
            ("tests/fixture.py", 1, "restricted"),
            ("tests/fixture.py", 2, "restricted"),
            ("tests/fixture.py", 3, "restricted"),
        ])

    def test_iac_files_and_allow_marker_exempt(self) -> None:
        r = Repo()
        r.write("main.tf", 'cidr_block = "10.0.0.0/16"\n')
        r.write("envs/prod.tfvars", 'subnet = "10.0.1.0/24"\n')
        r.write("tests/test_redact.py", f'assert redact("{ADDR}")  # docs-boundary: allow\nx = "{ADDR}"\n')
        r.commit()
        self.assertEqual(self.kinds(r), [("tests/test_redact.py", 2, "restricted")])

    def test_internal_domain_only_when_named(self) -> None:
        r = Repo()
        r.write("a.md", "ssh core1.net.example.org, mail me@example.org\n")
        r.commit()
        self.assertEqual(self.kinds(r), [])
        self.assertEqual(self.kinds(r, "example.org"), [("a.md", 1, "restricted")])

    def test_wiki_ignore(self) -> None:
        r = Repo()
        r.write("docs/restricted/x.md", "secret-free\n")
        r.commit()
        self.assertEqual(self.kinds(r), [(".openwikiignore", 0, "wiki-ignore")])
        for entry in ("docs/restricted", "/docs/restricted/**", "docs/"):
            r.write(".openwikiignore", entry + "\n")
            self.assertEqual(self.kinds(r), [], entry)

    def test_outside_images_but_not_badges_or_relative(self) -> None:
        r = Repo()
        r.write("README.md", "\n".join([
            "![ci](https://github.com/psd401/x/actions/workflows/ci.yml/badge.svg)",
            "![l](https://img.shields.io/badge/license-MIT-blue)",
            "![shot](./docs/img/shot.png)",
            "![shot](https://i.imgur.com/abc.png)",
            '<img src="https://example.com/a.png" width=10>',
            "[link, not image](https://example.com/a.png)",
        ]) + "\n")
        r.write("notes.txt", "![x](https://example.com/a.png)\n")
        r.commit()
        self.assertEqual(self.kinds(r), [("README.md", 4, "image"), ("README.md", 5, "image")])

    def test_binary_and_untracked_files_skipped(self) -> None:
        r = Repo()
        r.write("blob.bin", "x\0" + ADDR)
        r.commit()
        r.write("untracked.md", ADDR)
        self.assertEqual(self.kinds(r), [])


class PullRequestMode(unittest.TestCase):
    def test_only_added_lines_fail(self) -> None:
        r = Repo()
        r.write("old.md", f"{ADDR}\n")
        r.write("b.md", "line one\n")
        base = r.commit()
        r.write("b.md", f"line one\n![x](https://example.com/a.png)\n{MAC}\n")
        r.commit()
        code, out = r.run("--base", base)
        self.assertEqual(code, 1, out)
        self.assertIn("::error file=b.md,line=2::", out)
        self.assertIn("::error file=b.md,line=3::", out)
        self.assertIn("::warning file=old.md,line=1::", out)
        self.assertIn("docs boundary: 2 failing, 1 existing", out)

    def test_existing_findings_do_not_fail(self) -> None:
        r = Repo()
        r.write("old.md", f"{ADDR}\n")
        base = r.commit()
        r.write("new.md", "clean\n")
        r.commit()
        code, out = r.run("--base", base)
        self.assertEqual(code, 0, out)

    def test_wiki_ignore_always_fails_with_base(self) -> None:
        r = Repo()
        r.write("docs/restricted/x.md", "x\n")
        base = r.commit()
        r.write("y.md", "y\n")
        r.commit()
        code, out = r.run("--base", base)
        self.assertEqual(code, 1, out)
        self.assertIn("::error file=.openwikiignore::", out)

    def test_report_mode_never_fails(self) -> None:
        r = Repo()
        r.write("a.md", f"{ADDR}\n")
        r.commit()
        code, out = r.run()
        self.assertEqual(code, 0, out)
        self.assertIn("::warning file=a.md,line=1::", out)

    def test_no_value_is_printed(self) -> None:
        r = Repo()
        r.write("a.md", f"{ADDR} {MAC}\n![x](https://secret.example.com/p.png)\n")
        base = r.commit()
        r.write("a.md", f"{ADDR} {MAC}\n![x](https://secret.example.com/p.png)\n{ADDR}\n")
        r.commit()
        for args in ((), ("--base", base), ("--domain", "example.com")):
            _, out = r.run(*args)
            for value in (ADDR, MAC, "secret.example.com", "10.20"):
                self.assertNotIn(value, out, (args, value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
