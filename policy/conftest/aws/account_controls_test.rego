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

# One resource tagged psd:root = account-baseline does not make a plan the
# baseline root: every resource that carries tags must carry it. Otherwise a
# student-pii app root turns the app-root denies off with a single tag.
test_one_tagged_resource_does_not_make_an_app_root_the_baseline_root if {
	not acct_baseline_root with input as acct_plan([pii_marker, acct_baseline_marker])
	full := acct_dpp(acct_doc(acct_ids, acct_ids))
	findings := acct_findings(deny) with input as acct_plan([pii_marker, acct_baseline_marker, acct_policy(["create"], null, full, {})])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 1
	some m in findings
	contains(m, "student-pii app root")
}

# A resource with no tags_all (the account policy has none) does not count
# against the baseline root.
test_baseline_root_may_hold_resources_without_tags if {
	full := acct_dpp(acct_doc(acct_ids, acct_ids))
	acct_baseline_root with input as acct_plan([acct_baseline_marker, acct_policy(["create"], null, full, {})])
}

# A no-op change shows the resource's current tags_all in after, so a
# resource the plan leaves alone that is tagged but lacks psd:root still
# counts against the baseline root.
test_no_op_resource_without_the_root_tag_counts_against_the_baseline_root if {
	noop := object.union(pii_marker, {"change": {"actions": ["no-op"], "before": {"tags_all": pii_tags}, "after": {"tags_all": pii_tags}}})
	not acct_baseline_root with input as acct_plan([acct_baseline_marker, noop])
}

# A delete has no after, so it is judged by before: deleting an untagged
# resource does not hide it from the check, and the baseline root destroying
# its own tagged resource stays the baseline root.
test_delete_is_judged_by_before_tags_all if {
	gone := object.union(pii_marker, {"change": {"actions": ["delete"], "before": {"tags_all": pii_tags}, "after": null}})
	not acct_baseline_root with input as acct_plan([acct_baseline_marker, gone])
	own := {
		"address": "aws_iam_role.breakglass",
		"type": "aws_iam_role",
		"change": {"actions": ["delete"], "before": acct_baseline_marker.change.after, "after": null},
	}
	acct_baseline_root with input as acct_plan([own])
}

# The root-tag deny's findings only. Its message starts with the tag, not an
# address, because the plan as a whole is what it judges.
acct_root_tag_findings(msgs) := {m | some m in msgs; startswith(m, "psd:root = account-baseline:")}

acct_untagged(address, actions, before, after, after_unknown) := {
	"address": address,
	"type": "aws_s3_bucket",
	"change": {"actions": actions, "before": before, "after": after, "after_unknown": after_unknown},
}

# A plan that carries the tag on some resources and not on others is neither
# the baseline root nor, unless it is tagged student-pii, an app root. Without
# its own deny no account rule would judge it at all.
test_plan_with_the_root_tag_on_some_resources_only_is_denied if {
	extra := acct_untagged("aws_s3_bucket.extra", ["create"], null, {"tags_all": internal_tags}, {})
	not acct_baseline_root with input as acct_plan([acct_baseline_marker, extra])
	findings := acct_root_tag_findings(deny) with input as acct_plan([acct_baseline_marker, extra])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 1
	some m in findings
	contains(m, "aws_iam_role.breakglass")
	contains(m, "aws_s3_bucket.extra")
	endswith(m, "(08-iac.md#student-pii-account-posture)")
}

test_plan_deleting_a_resource_without_the_root_tag_is_denied if {
	gone := acct_untagged("aws_s3_bucket.old", ["delete"], {"tags_all": internal_tags}, null, {})
	findings := acct_root_tag_findings(deny) with input as acct_plan([acct_baseline_marker, gone])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 1
	some m in findings
	contains(m, "aws_s3_bucket.old")
}

# terraform show -json leaves a wholly unknown tags_all out of after and sets
# after_unknown.tags_all to true. Unknown counts as not carrying the tag.
test_tags_all_unknown_at_plan_counts_against_the_baseline_root if {
	unknown := acct_untagged("aws_s3_bucket.computed", ["create"], null, {}, {"tags_all": true})
	not acct_baseline_root with input as acct_plan([acct_baseline_marker, unknown])
	findings := acct_root_tag_findings(deny) with input as acct_plan([acct_baseline_marker, unknown])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 1
	some m in findings
	contains(m, "aws_s3_bucket.computed")
	contains(m, "not known at plan time")
}

# The baseline root is tagged internal. A student-pii root that puts the root
# tag on every resource, through default_tags or by hand, stays an app root:
# the app-root denies still fire, and the root-tag deny names the conflict.
test_student_pii_root_tagged_on_every_resource_stays_an_app_root if {
	both := object.union(pii_marker, {"change": {"actions": ["create"], "after": {"tags_all": object.union(pii_tags, {"psd:root": "account-baseline"})}}})
	policy := acct_policy(["create"], null, acct_dpp(acct_doc(acct_ids, acct_ids)), {})
	not acct_baseline_root with input as acct_plan([both, policy])
	acct_app_root with input as acct_plan([both, policy])
	msgs := deny with input as acct_plan([both, policy])
		with data.student_pii_account as data.acct_student_pii_account
	owned := acct_findings(msgs)
	count(owned) == 1
	some o in owned
	contains(o, "student-pii app root")
	tagged := acct_root_tag_findings(msgs)
	count(tagged) == 1
	some t in tagged
	contains(t, "aws_s3_bucket.data")
	contains(t, "psd:data-classification = student-pii")
}

# terraform show -json lists one unknown tag value as
# after_unknown.tags_all.<key> = true and leaves the key out of after. An
# unknown psd:root or psd:data-classification counts against the baseline
# root, and the message says unknown, not missing.
test_root_or_classification_tag_unknown_at_plan_counts_against_the_baseline_root if {
	every key in ["psd:root", "psd:data-classification"] {
		known := object.remove(acct_baseline_marker.change.after.tags_all, {key})
		rc := acct_untagged("aws_s3_bucket.computed", ["create"], null, {"tags_all": known}, {"tags_all": {key: true}})
		not acct_baseline_root with input as acct_plan([acct_baseline_marker, rc])
		findings := acct_root_tag_findings(deny) with input as acct_plan([acct_baseline_marker, rc])
			with data.student_pii_account as data.acct_student_pii_account
		count(findings) == 1
		some m in findings
		contains(m, "aws_s3_bucket.computed has tags_all values not known at plan time")
		not contains(m, "aws_s3_bucket.computed does not carry it")
	}
}

# Any other tag may be unknown at plan time.
test_other_tag_unknown_at_plan_does_not_count_against_the_baseline_root if {
	rc := acct_untagged("aws_s3_bucket.named", ["create"], null, {"tags_all": acct_baseline_marker.change.after.tags_all}, {"tags_all": {"Name": true}})
	acct_baseline_root with input as acct_plan([acct_baseline_marker, rc])
}

acct_cap_ok(m, 0) if not contains(m, " more")

acct_cap_ok(m, more) if {
	more > 0
	contains(m, sprintf("and %d more", [more]))
	not contains(m, "aws_s3_bucket.extra6")
}

# The message names at most five conflicts and counts the rest: five are all
# named, six and seven name five and count one and two more.
test_root_tag_deny_caps_the_conflicts_it_names if {
	every n, more in {5: 0, 6: 1, 7: 2} {
		extras := [acct_untagged(sprintf("aws_s3_bucket.extra%d", [i]), ["create"], null, {"tags_all": internal_tags}, {}) | some i in numbers.range(1, n)]
		findings := acct_root_tag_findings(deny) with input as acct_plan(array.concat([acct_baseline_marker], extras))
			with data.student_pii_account as data.acct_student_pii_account
		count(findings) == 1
		some m in findings
		contains(m, "aws_s3_bucket.extra5")
		acct_cap_ok(m, more)
	}
}

# A plan with no root tag anywhere, and the baseline fixture, get no root-tag deny.
test_root_tag_deny_is_silent_without_a_conflict if {
	count(acct_root_tag_findings(deny)) == 0 with input as acct_plan([pii_marker])
	count(acct_root_tag_findings(deny)) == 0 with input as data.acct_plan_unrelated
	count(acct_root_tag_findings(deny)) == 0 with input as data.acct_plan_baseline
		with data.student_pii_account as data.acct_student_pii_account
}
