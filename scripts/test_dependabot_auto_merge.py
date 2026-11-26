# ABOUTME: Offline tests for the decision in reusable-dependabot-auto-merge.yml: which Dependabot updates turn auto-merge on.
# ABOUTME: Run: python3 -I scripts/test_dependabot_auto_merge.py (CI: psd-ci.yml). Needs jq, which GitHub's runners carry.
"""Runs the workflow's own jq program, read out of the workflow file, against
update lists shaped like dependabot/fetch-metadata's updated-dependencies-json,
with psd_reusable_pins off and on."""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/reusable-dependabot-auto-merge.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
PROGRAM = re.search(r"""jq -e --arg pins "\$PSD_PINS" '(.*?)' \\\n""", TEXT, re.S)


def decide(updates: object, pins: bool) -> bool:
    """True when the workflow would turn auto-merge on."""
    text = updates if isinstance(updates, str) else json.dumps(updates)
    run = subprocess.run(["jq", "-e", "--arg", "pins", "true" if pins else "false", PROGRAM.group(1)],
                         input=text, capture_output=True, text=True, check=False)
    return run.returncode == 0


def dev(update: str = "patch", kind: str = "direct:development") -> dict:
    return {"dependencyName": "left-pad", "dependencyType": kind,
            "updateType": f"version-update:semver-{update}", "packageEcosystem": "npm_and_yarn"}


def pin(update: str = "minor", name: str = "PSD401/.github/.github/workflows/reusable-psd-ci.yml") -> dict:
    # Dependabot types every github-actions update direct:production.
    return {"dependencyName": name, "dependencyType": "direct:production",
            "updateType": f"version-update:semver-{update}", "packageEcosystem": "github_actions"}


class Decision(unittest.TestCase):
    def check(self, updates: object, off: bool, on: bool) -> None:
        self.assertEqual((decide(updates, False), decide(updates, True)), (off, on))

    def test_the_program_is_read_from_the_workflow(self) -> None:
        self.assertIsNotNone(PROGRAM)
        self.assertIn("PSD_PINS: ${{ inputs.psd_reusable_pins }}", TEXT)

    def test_the_input_is_off_by_default(self) -> None:
        block = re.search(r"\n      psd_reusable_pins:\n(?:        .*\n)+", TEXT).group(0)
        self.assertIn("type: boolean", block)
        self.assertIn("default: false", block)

    def test_dev_dependency_patch_merges_either_way(self) -> None:
        self.check([dev()], True, True)

    def test_dev_dependency_minor_never_merges(self) -> None:
        self.check([dev("minor")], False, False)

    def test_production_dependency_patch_never_merges(self) -> None:
        self.check([dev(kind="direct:production")], False, False)

    def test_reusable_pin_minor_and_patch_merge_only_with_the_input(self) -> None:
        self.check([pin("minor")], False, True)
        self.check([pin("patch")], False, True)

    def test_reusable_pin_major_never_merges(self) -> None:
        self.check([pin("major")], False, False)

    def test_owner_case_does_not_matter(self) -> None:
        self.check([pin(name="psd401/.github/.github/workflows/reusable-security-scan.yml")], False, True)

    def test_a_group_of_pins_merges_only_with_the_input(self) -> None:
        self.check([pin(), pin("patch"), pin(), pin()], False, True)

    def test_a_pin_grouped_with_another_action_never_merges(self) -> None:
        self.check([pin(), dict(pin(), dependencyName="astral-sh/setup-uv")], False, False)

    def test_another_action_never_merges(self) -> None:
        self.check([dict(pin(), dependencyName="astral-sh/setup-uv")], False, False)

    def test_look_alike_names_never_merge(self) -> None:
        for name in ("PSD401/.github-evil/.github/workflows/reusable-x.yml",
                     "notPSD401/.github/.github/workflows/reusable-x.yml",
                     "PSD401/.github/.github/workflows/release.yml",
                     "x/PSD401/.github/.github/workflows/reusable-x.yml"):
            with self.subTest(name=name):
                self.check([pin(name=name)], False, False)

    def test_a_pin_name_in_another_ecosystem_never_merges(self) -> None:
        self.check([dict(pin(), packageEcosystem="npm_and_yarn")], False, False)

    def test_missing_fields_never_merge(self) -> None:
        self.check([dict(pin(), updateType="")], False, False)
        self.check([{k: v for k, v in pin().items() if k != "dependencyName"}], False, False)
        self.check([{k: v for k, v in pin().items() if k != "packageEcosystem"}], False, False)

    def test_empty_or_unreadable_metadata_never_merges(self) -> None:
        self.check([], False, False)
        self.check("", False, False)
        self.check("garbage{", False, False)
        self.check({"dependencyName": "x"}, False, False)


if __name__ == "__main__":
    unittest.main()
