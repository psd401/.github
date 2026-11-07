# ABOUTME: Every repo-relative file path named in the IaC policy, schemas, scripts, tools, docs and
# ABOUTME: reusables must exist here; CODEOWNERS and iac-tests.yml cover .github/actionlint.yaml.
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCES = sorted(
    p for d in ("policy", "schemas/iac", "scripts/iac", "tools/iac") for p in (ROOT / d).rglob("*")
    if p.is_file() and "__pycache__" not in p.parts and "fixtures" not in p.parts
) + [ROOT / ".github/workflows" / n for n in (
    "reusable-env-file-check.yml", "reusable-iac-checks.yml", "reusable-onprem-checks.yml", "iac-tests.yml")] + [
    ROOT / "README.md", ROOT / "RELEASING.md"]
# A path that starts at a top-level directory of this repo and names a file.
# Not preceded by a word char or "/", so "_policy/schemas/..." checkout paths
# and URLs are skipped; "<" and "*" end the match, so placeholders and globs drop out.
PATH = re.compile(r"(?<![\w/.<-])((?:policy|schemas|scripts|tools)/[\w./-]+\.(?:json|rego|sh|py|txt|in|yml|yaml|md))\b")


def referenced(p):
    return sorted(set(PATH.findall(p.read_text(errors="ignore"))))


@pytest.mark.parametrize("src", SOURCES, ids=[str(p.relative_to(ROOT)) for p in SOURCES])
def test_named_paths_exist(src):
    missing = [r for r in referenced(src) if not (ROOT / r).exists()]
    assert not missing, f"{src.relative_to(ROOT)} names {missing}"


def owners(path):
    for line in (ROOT / ".github/CODEOWNERS").read_text().splitlines():
        parts = line.split()
        if parts and parts[0] == path:
            return parts[1:]
    return None


def test_actionlint_config_has_the_workflow_owners_and_triggers_iac_tests():
    import yaml
    assert owners("/.github/actionlint.yaml") == owners("/.github/workflows/")
    wf = yaml.safe_load((ROOT / ".github/workflows/iac-tests.yml").read_text())
    assert ".github/actionlint.yaml" in wf.get("on", wf.get(True))["pull_request"]["paths"]
