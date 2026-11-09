# ABOUTME: Static checks on the account-baseline apply-role boundary template: it allows exactly the
# ABOUTME: log-control writes the app boundary denies, never logs:Unmask, and renders to valid JSON.
"""The account baseline root owns the account data protection policy and the
Bedrock logging configuration (08-iac.md, Student PII account posture). Its
apply role runs under templates/account-baseline/boundary/, not the app
deploy-role boundary, which denies those writes with no carve-out."""
import fnmatch
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "templates/account-baseline/boundary/deploy-role-boundary.json.tmpl"
APP_TEMPLATE = ROOT / "templates/terraform-app/boundary/deploy-role-boundary.json.tmpl"
SERVICE_REFERENCE = ROOT / "scripts/iac/fixtures/iam-service-reference-actions.json"

APP_STUDENT_PII_DENIES = ("DenyLogsUnmask", "DenyAccountLogPolicy", "DenyBedrockLoggingConfig", "DenyLogExport")
BASELINE_WRITES = {
    "logs:PutAccountPolicy",
    "logs:DeleteAccountPolicy",
    "bedrock:PutModelInvocationLoggingConfiguration",
    "bedrock:DeleteModelInvocationLoggingConfiguration",
}


def statements(path=TEMPLATE):
    return json.loads(path.read_text())["Statement"]


def as_list(value):
    return [value] if isinstance(value, str) else list(value)


def covers(stmt, action):
    """True when the statement's Action (or NotAction) applies to action."""
    def match(patterns):
        return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in as_list(patterns))
    if "NotAction" in stmt:
        return not match(stmt["NotAction"])
    return match(stmt.get("Action", []))


def allowed(stmts, action):
    """Allowed on Resource *: some Allow on * covers it and no Deny covers it."""
    allow = any(s["Effect"] == "Allow" and covers(s, action) and "*" in as_list(s["Resource"]) for s in stmts)
    deny = any(s["Effect"] == "Deny" and covers(s, action) for s in stmts)
    return allow and not deny


def test_allows_exactly_the_log_control_writes_the_app_boundary_denies():
    if not APP_TEMPLATE.exists():
        pytest.skip("the app deploy-role boundary template lives in psd-dev-standards")
    by_sid = {s["Sid"]: s for s in statements(APP_TEMPLATE)}
    app_denied = {a for sid in APP_STUDENT_PII_DENIES for a in as_list(by_sid[sid]["Action"])}
    assert BASELINE_WRITES <= app_denied, f"the app boundary no longer denies {BASELINE_WRITES - app_denied}"
    granted = {a for a in app_denied if allowed(statements(), a)}
    assert granted == BASELINE_WRITES


def test_apply_role_can_neither_unmask_nor_assume_the_break_glass_role():
    by_sid = {s["Sid"]: s for s in statements()}
    deny = by_sid.get("DenyLogsUnmask")
    assert deny is not None, "no DenyLogsUnmask statement"
    assert (deny["Effect"], as_list(deny["Action"]), deny["Resource"]) == ("Deny", ["logs:Unmask"], "*")
    assert "Condition" not in deny
    assume = by_sid.get("DenyAssumeBreakGlass")
    assert assume is not None, "no DenyAssumeBreakGlass statement"
    assert (assume["Effect"], as_list(assume["Action"])) == ("Deny", ["sts:AssumeRole"])
    assert as_list(assume["Resource"]) == ["arn:aws:iam::*:role/<breakglass-role-name>"]
    assert "Condition" not in assume


SAMPLE_VALUES = {
    "<repo>": "account-baseline",
    "<region>": "us-west-2",
    "<account-alias>": "prod-alias",
    "<breakglass-role-name>": "district-breakglass-unmask",
}


def test_template_renders_to_valid_json():
    text = TEMPLATE.read_text()
    document = json.loads(text)
    documented = set(re.findall(r"<[a-z-]+>", document["_comment"]))
    body = json.dumps({k: v for k, v in document.items() if k != "_comment"})
    used = set(re.findall(r"<[a-z_-]+>", body))
    assert used <= documented, f"placeholders the _comment does not name: {used - documented}"
    assert documented <= used, f"the _comment names placeholders no statement uses: {documented - used}"
    assert used <= set(SAMPLE_VALUES), f"no sample value for {used - set(SAMPLE_VALUES)}"
    rendered = text
    for placeholder, value in SAMPLE_VALUES.items():
        rendered = rendered.replace(placeholder, value)
    assert not re.search(r"<[a-z_-]+>", rendered)
    assert json.loads(rendered)["Statement"]


def test_every_logs_and_bedrock_action_exists_in_the_service_reference():
    ref = json.loads(SERVICE_REFERENCE.read_text())
    known = {f"{svc}:{name}" for svc, entry in ref["services"].items() for name in entry["actions"]}
    used = {a for s in statements() for a in as_list(s.get("Action", []))
            if a.split(":")[0] in ref["services"] and "*" not in a}
    assert BASELINE_WRITES <= used
    assert not sorted(used - known), f"not in the service reference: {sorted(used - known)}"


PERMISSION_SET_POLICY = ROOT / "templates/account-baseline/breakglass-permission-set-policy.json.tmpl"


def test_breakglass_permission_set_may_only_assume_the_break_glass_role():
    """The break-glass trust accepts this permission set's role, so the
    permission set grants nothing but the assumption and its source identity."""
    document = json.loads(PERMISSION_SET_POLICY.read_text())
    assert set(re.findall(r"<[a-z-]+>", document["_comment"])) == {"<breakglass-role-name>"}
    body = [{k: v for k, v in s.items() if not k.startswith("_")} for s in document["Statement"]]
    assert body == [{
        "Sid": "AssumeBreakGlassRole",
        "Effect": "Allow",
        "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
        "Resource": "arn:aws:iam::*:role/<breakglass-role-name>",
    }]
    rendered = PERMISSION_SET_POLICY.read_text().replace("<breakglass-role-name>", SAMPLE_VALUES["<breakglass-role-name>"])
    assert not re.search(r"<[a-z_-]+>", rendered)
