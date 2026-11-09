# ABOUTME: Tests for account_controls.rego: the account-baseline root's data protection policy lists every
# ABOUTME: required identifier, and a student-pii app root never creates, updates or deletes that policy.
package aws

# data.acct_student_pii_account (fixtures/aws/acct_student_pii_account.json) is
# the derived cloud.aws.student_pii data for scripts/iac/fixtures/env-student-pii.yml.
# data.acct_plan_baseline and data.acct_plan_unrelated are trimmed
# `terraform show -json` output of hashicorp/aws v6.70.0 plans. Tests bind the
# derived data with `with data.student_pii_account as`, so no other test in
# this package sees it.

acct_ids := [
	"arn:aws:dataprotection::aws:data-identifier/Name",
	"arn:aws:dataprotection::aws:data-identifier/EmailAddress",
	"arn:aws:dataprotection::aws:data-identifier/Address",
	"StudentId",
]

acct_doc(audit, deidentify) := json.marshal({
	"Name": "student-pii", "Version": "2021-06-01",
	"Configuration": {"CustomDataIdentifier": [{"Name": "StudentId", "Regex": "S[0-9]{7}"}]},
	"Statement": [
		{"Sid": "audit", "DataIdentifier": audit, "Operation": {"Audit": {"FindingsDestination": {}}}},
		{"Sid": "redact", "DataIdentifier": deidentify, "Operation": {"Deidentify": {"MaskConfig": {}}}},
	],
})

acct_dpp(doc) := {"policy_name": "student-pii", "policy_type": "DATA_PROTECTION_POLICY", "scope": "ALL", "policy_document": doc}

acct_address := "aws_cloudwatch_log_account_policy.student_pii"

acct_policy(actions, before, after, after_unknown) := {
	"address": acct_address,
	"type": "aws_cloudwatch_log_account_policy",
	"change": {"actions": actions, "before": before, "after": after, "after_unknown": after_unknown},
}

acct_baseline_marker := {
	"address": "aws_iam_role.breakglass",
	"type": "aws_iam_role",
	"change": {"actions": ["create"], "after": {"name": "district-breakglass-unmask", "tags_all": {"psd:data-classification": "internal", "psd:root": "account-baseline"}}},
}

acct_plan(rcs) := {"configuration": {"provider_config": {}}, "resource_changes": rcs}

# Findings for the account policy's address only, so other rules' findings
# on the same plan stay out of the count.
acct_findings(msgs) := {m | some m in msgs; startswith(m, sprintf("%s:", [acct_address]))}

acct_baseline_findings(rc) := findings if {
	findings := acct_findings(deny) with input as acct_plan([acct_baseline_marker, rc])
		with data.student_pii_account as data.acct_student_pii_account
}

test_student_pii_app_root_creating_updating_or_deleting_the_account_policy_denied if {
	full := acct_dpp(acct_doc(acct_ids, acct_ids))
	every rc in [
		acct_policy(["create"], null, full, {}),
		acct_policy(["update"], full, full, {}),
		acct_policy(["delete"], full, null, {}),
		acct_policy(["delete", "create"], full, full, {}),
	] {
		findings := acct_findings(deny) with input as acct_plan([pii_marker, rc])
		count(findings) == 1
		some m in findings
		contains(m, "student-pii app root")
		contains(m, "templates/account-baseline/")
		endswith(m, "(08-iac.md#student-pii-account-posture)")
	}
}

test_account_policy_rule_ignores_exceptions_entries if {
	rc := acct_policy(["create"], null, acct_dpp(acct_doc(acct_ids, acct_ids)), {})
	findings := acct_findings(deny) with input as acct_plan([pii_marker, rc])
		with data.exceptions as [
			pii_entry("acct-posture", acct_address),
			object.union(pii_entry("acct-posture-2", acct_address), {"standard": "08-iac.md#student-pii-account-posture"}),
		]
	count(findings) == 1
}

test_baseline_root_with_every_identifier_passes if {
	count(deny) == 0 with input as data.acct_plan_baseline
		with data.student_pii_account as data.acct_student_pii_account
}

test_baseline_root_policy_missing_a_custom_identifier_denied if {
	managed := array.slice(acct_ids, 0, 3)
	findings := acct_baseline_findings(acct_policy(["create"], null, acct_dpp(acct_doc(acct_ids, managed)), {}))
	count(findings) == 1
	some m in findings
	contains(m, "the Deidentify statement does not list StudentId")
	endswith(m, "(08-iac.md#student-pii-account-posture)")
}

test_baseline_root_policy_missing_a_managed_identifier_denied if {
	no_address := [i | some i in acct_ids; i != "arn:aws:dataprotection::aws:data-identifier/Address"]
	findings := acct_baseline_findings(acct_policy(["update"], null, acct_dpp(acct_doc(no_address, acct_ids)), {}))
	count(findings) == 1
	some m in findings
	contains(m, "the Audit statement does not list arn:aws:dataprotection::aws:data-identifier/Address")
}

test_baseline_root_policy_document_unknown_at_plan_denied if {
	after := object.remove(acct_dpp(""), {"policy_document"})
	findings := acct_baseline_findings(acct_policy(["create"], null, after, {"policy_document": true}))
	count(findings) == 1
	some m in findings
	contains(m, "policy_document is not known JSON at plan time")
}

test_baseline_root_without_student_pii_account_data_denied if {
	no_permission_set := object.remove(data.acct_student_pii_account, {"breakglass_permission_set_name"})
	every acct_data in [null, {"present": false, "breakglass_role_name": "", "breakglass_permission_set_name": "", "managed_identifiers": [], "custom_identifier_names": []}, no_permission_set] {
		msgs := deny with input as data.acct_plan_baseline with data.student_pii_account as acct_data
		some m in msgs
		startswith(m, "account-baseline root: data.student_pii_account is missing or incomplete")
		endswith(m, "(08-iac.md#student-pii-account-posture)")
	}
	some m in deny with input as data.acct_plan_baseline
	startswith(m, "account-baseline root: data.student_pii_account is missing or incomplete")
}

# acct_plan_unrelated is an internal root (no psd:root tag) that plans an
# account data protection policy listing only Name, a role policy granting
# logs:* on "*", and Bedrock logging with every content flag at the provider
# default of true. None of the student-pii account rules apply to it.
test_unrelated_root_unaffected if {
	count(deny) == 0 with input as data.acct_plan_unrelated
	count(deny) == 0 with input as data.acct_plan_unrelated
		with data.student_pii_account as data.acct_student_pii_account
}
