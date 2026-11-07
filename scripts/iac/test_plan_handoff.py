# ABOUTME: Static checks that the binary Terraform plan leaves the plan job only
# ABOUTME: age-encrypted, and that the apply job decrypts it before terraform apply.
"""The binary plan holds resolved secrets in plaintext, and any repo reader can
download a run's artifacts (standards/08-iac.md, 'Saved-plan
handoff'). The standards owner approved age encryption to a per-environment key, 2026-10-23."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
REUSABLE = ROOT / ".github/workflows/reusable-iac-checks.yml"
APPLY_IF = "inputs.apply && github.event_name != 'schedule'"


def load(p):
    return yaml.safe_load(p.read_text())


def index_of(steps, pred, what):
    hits = [i for i, s in enumerate(steps) if pred(s)]
    assert hits, f"no step {what}"
    return hits[0]


def runs(text):
    return lambda s: text in (s.get("run") or "")


def uses(action):
    return lambda s: (s.get("uses") or "").startswith(action)


def strip_expr(v):
    return str(v).replace("${{", "").replace("}}", "").strip()


def test_reusable_declares_the_recipient_input_and_the_key_secret():
    call = load(REUSABLE)["on"]["workflow_call"]
    assert call["inputs"]["plan_recipient"]["type"] == "string"
    assert call["secrets"]["PSD_PLAN_KEY"]["required"] is False


def test_plan_job_never_uploads_the_bare_binary_plan():
    steps = load(REUSABLE)["jobs"]["plan"]["steps"]
    for s in steps:
        if uses("actions/upload-artifact")(s):
            lines = [l.strip() for l in s["with"]["path"].splitlines() if l.strip()]
            assert not any(l.endswith("/tfplan") or l == "tfplan" for l in lines), lines
            assert any(l.endswith("/tfplan.age") for l in lines), lines


def test_plan_job_seals_before_upload_under_the_apply_condition():
    steps = load(REUSABLE)["jobs"]["plan"]["steps"]
    install = index_of(steps, runs("install_age.sh"), "running install_age.sh")
    seal = index_of(steps, runs("plan_seal.py\" seal"), "running plan_seal.py seal")
    upload = index_of(steps, uses("actions/upload-artifact"), "uploading the plan")
    assert install < seal < upload
    for i in (install, seal):
        assert strip_expr(steps[i]["if"]) == APPLY_IF
    assert strip_expr(steps[seal]["env"]["PLAN_RECIPIENT"]) == "inputs.plan_recipient"


def test_apply_job_opens_the_plan_with_the_environment_key_before_apply():
    steps = load(REUSABLE)["jobs"]["apply"]["steps"]
    download = index_of(steps, uses("actions/download-artifact"), "downloading the plan")
    install = index_of(steps, runs("install_age.sh"), "running install_age.sh")
    opened = index_of(steps, runs("plan_seal.py\" open"), "running plan_seal.py open")
    apply = index_of(steps, runs("terraform apply"), "running terraform apply")
    assert download < opened < apply
    assert install < opened
    assert strip_expr(steps[opened]["env"]["PSD_PLAN_KEY"]) == "secrets.PSD_PLAN_KEY"

