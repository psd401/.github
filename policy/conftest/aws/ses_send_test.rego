# ABOUTME: Tests for ses_send.rego: SES send grants are scoped, pin ses:FromAddress to the environment file's
# ABOUTME: approved list, deny when that list is missing, and never come from a broad AWS managed policy.
package aws

# Tests for ses_send.rego (17-email-sending.md rules 3 and 9). Policies are
# built as Rego objects and serialized with json.marshal, the same string
# shape `tofu show -json` puts in `policy`.
#
# data.ses_env_from_addresses (fixtures/aws/ses_env_from_addresses.json) is
# the derived cloud.aws.ses data for scripts/iac/fixtures/env-student-pii.yml.
# Tests bind it with `with data.ses_from_addresses as`, so no other test in
# this package sees it.

identity_arn := "arn:aws:ses:us-west-2:<account-id>:identity/<district-domain>"

set_arn := "arn:aws:ses:us-west-2:<account-id>:configuration-set/app-prod-transactional"

base_ses_stmt := {
	"Sid": "Send",
	"Effect": "Allow",
	"Action": ["ses:SendEmail", "ses:SendRawEmail"],
	"Resource": [identity_arn, set_arn],
	"Condition": {"StringEquals": {"ses:FromAddress": "app-alerts@<district-domain>"}},
}

# Top-level keys in overrides replace the base statement's (object.union alone
# would merge a Condition override into the base condition).
ses_stmt(overrides) := object.union(object.remove(base_ses_stmt, object.keys(overrides)), overrides)

policy_doc(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

policy_rc(type, policy) := {
	"address": sprintf("%s.send", [type]),
	"type": type,
	"mode": "managed",
	"change": {"actions": ["create"], "after": {"policy": policy}, "after_unknown": {}},
}

ses_plan(rcs) := {"configuration": {"provider_config": {}}, "resource_changes": rcs}

# deny and warn for a plan, with the approved From list bound.
ses_deny_on(plan) := d if {
	d := deny with input as plan with data.ses_from_addresses as data.ses_env_from_addresses
}

ses_warn_on(plan) := w if {
	w := warn with input as plan with data.ses_from_addresses as data.ses_env_from_addresses
}

ses_denies(stmt) := ses_deny_on(ses_plan([policy_rc("aws_iam_role_policy", policy_doc([stmt]))]))

test_ses_pinned_scoped_statement_passes if {
	count(ses_denies(ses_stmt({}))) == 0
}

denied_without_from_address(type) if {
	stmt := object.remove(ses_stmt({}), ["Condition"])
	some msg in ses_deny_on(ses_plan([policy_rc(type, policy_doc([stmt]))]))
	contains(msg, "no ses:FromAddress condition")
}

test_ses_each_policy_type_denied_without_from_address if {
	every type in iam_policy_types {
		denied_without_from_address(type)
	}
}

test_ses_resource_star_denied if {
	some msg in ses_denies(ses_stmt({"Resource": "*"}))
	contains(msg, "Resource \"*\"")
	contains(msg, "rule 9")
}

test_ses_resource_star_in_list_denied if {
	some msg in ses_denies(ses_stmt({"Resource": [identity_arn, "*"]}))
	contains(msg, "Resource \"*\"")
}

test_ses_not_resource_denied if {
	stmt := object.union(object.remove(ses_stmt({}), ["Resource"]), {"NotResource": "arn:aws:ses:us-west-2:<account-id>:identity/other"})
	some msg in ses_denies(stmt)
	contains(msg, "NotResource")
}

test_ses_missing_from_address_denied if {
	some msg in ses_denies(object.remove(ses_stmt({}), ["Condition"]))
	contains(msg, "statement \"Send\" allows SES send with no ses:FromAddress condition")
}

test_ses_if_exists_condition_does_not_pin if {
	some msg in ses_denies(ses_stmt({"Condition": {"StringEqualsIfExists": {"ses:FromAddress": "app-alerts@<district-domain>"}}}))
	contains(msg, "no ses:FromAddress condition")
}

test_ses_other_condition_key_does_not_pin if {
	some msg in ses_denies(ses_stmt({"Condition": {"StringEquals": {"ses:FromDisplayName": "App"}}}))
	contains(msg, "no ses:FromAddress condition")
}

test_ses_unapproved_from_address_denied if {
	some msg in ses_denies(ses_stmt({"Condition": {"StringEquals": {"ses:FromAddress": ["app-alerts@<district-domain>", "someone@<district-domain>"]}}}))
	contains(msg, "someone@<district-domain>")
	contains(msg, "not an approved From address")
	contains(msg, "cloud.aws.ses.approved_from_addresses")
	not contains(msg, "app-alerts")
}

test_ses_wildcard_from_address_denied if {
	some msg in ses_denies(ses_stmt({"Condition": {"StringLike": {"ses:FromAddress": "*@<district-domain>"}}}))
	contains(msg, "not an approved From address")
}

test_ses_approved_aliases_and_variants_pass if {
	stmt := ses_stmt({"Condition": {
		"ForAllValues:StringLike": {"SES:FromAddress": ["App-Alarms@<district-domain>", "app-verification@<district-domain>"]},
		"StringEqualsIgnoreCase": {"ses:fromaddress": "team-alerts@<district-domain>"},
	}})
	count(ses_denies(stmt)) == 0
}

test_ses_every_listed_address_passes if {
	every addr in data.ses_env_from_addresses.approved_from_addresses {
		count(ses_denies(ses_stmt({"Condition": {"StringEquals": {"ses:FromAddress": addr}}}))) == 0
	}
}

test_ses_wildcard_actions_count_as_send if {
	every action in ["ses:*", "*", "ses:Send*", "SES:SENDEMAIL", "ses:SendRaw?mail", ["s3:GetObject", "ses:*"]] {
		some msg in ses_denies(ses_stmt({"Action": action, "Resource": "*"}))
		contains(msg, "Resource \"*\"")
	}
}

test_ses_not_action_that_leaves_send_counts if {
	stmt := object.union(object.remove(ses_stmt({}), ["Action"]), {"NotAction": "iam:*", "Resource": "*"})
	some msg in ses_denies(stmt)
	contains(msg, "Resource \"*\"")
}

test_ses_not_action_excluding_every_send_passes if {
	stmt := object.union(object.remove(ses_stmt({}), ["Action", "Condition"]), {"NotAction": "ses:*", "Resource": "*"})
	count(ses_denies(stmt)) == 0
}

test_ses_non_send_ses_action_passes if {
	count(ses_denies(ses_stmt({"Action": ["ses:GetAccount", "ses:ListIdentities"], "Resource": "*", "Condition": {}}))) == 0
}

test_ses_deny_statement_passes if {
	count(ses_denies(ses_stmt({"Effect": "Deny", "Resource": "*", "Condition": {}}))) == 0
}

test_ses_single_statement_object_checked if {
	doc := json.marshal({"Version": "2012-10-17", "Statement": ses_stmt({"Resource": "*"})})
	some msg in ses_deny_on(ses_plan([policy_rc("aws_iam_policy", doc)]))
	contains(msg, "Resource \"*\"")
}

test_ses_statement_without_sid_labelled_by_index if {
	stmt := object.remove(ses_stmt({"Resource": "*"}), ["Sid"])
	some msg in ses_deny_on(ses_plan([policy_rc("aws_iam_policy", policy_doc([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, stmt]))]))
	contains(msg, "aws_iam_policy.send: IAM statement 1 allows SES send on Resource")
}

test_ses_role_inline_policy_checked if {
	role := {
		"address": "aws_iam_role.app",
		"type": "aws_iam_role",
		"mode": "managed",
		"change": {"actions": ["update"], "after": {"inline_policy": [{"name": "send", "policy": policy_doc([ses_stmt({"Resource": "*"})])}]}},
	}
	some msg in ses_deny_on(ses_plan([role]))
	contains(msg, "aws_iam_role.app inline_policy \"send\"")
}

test_ses_deleted_policy_not_checked if {
	rc := object.union(policy_rc("aws_iam_policy", policy_doc([ses_stmt({"Resource": "*"})])), {"change": {"actions": ["delete"], "after": null}})
	count(ses_deny_on(ses_plan([rc]))) == 0
}

test_ses_unknown_policy_skipped_with_warning if {
	rc := {
		"address": "aws_iam_role_policy.send",
		"type": "aws_iam_role_policy",
		"mode": "managed",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {"policy": true}},
	}
	count(ses_deny_on(ses_plan([rc]))) == 0
	some msg in ses_warn_on(ses_plan([rc]))
	contains(msg, "aws_iam_role_policy.send: policy is unknown until apply")
}

role_rc(after, after_unknown) := {
	"address": "aws_iam_role.app",
	"type": "aws_iam_role",
	"mode": "managed",
	"change": {"actions": ["create"], "after": after, "after_unknown": after_unknown},
}

test_ses_unknown_role_inline_policy_skipped_with_warning if {
	rc := role_rc({"inline_policy": [{"name": "send"}]}, {"inline_policy": [{"policy": true}]})
	count(ses_deny_on(ses_plan([rc]))) == 0
	some msg in ses_warn_on(ses_plan([rc]))
	contains(msg, "aws_iam_role.app: an inline_policy is unknown until apply")
}

# What hashicorp/aws 6.20.0 plans for a new role with neither attribute set.
test_ses_new_role_computed_attributes_no_warning if {
	rc := role_rc({"inline_policy": null, "managed_policy_arns": null}, {"inline_policy": true, "managed_policy_arns": true, "arn": true})
	count(ses_warn_on(ses_plan([rc]))) == 0
	count(ses_deny_on(ses_plan([rc]))) == 0
}

test_ses_known_role_inline_policy_no_warning if {
	role := {
		"address": "aws_iam_role.app",
		"type": "aws_iam_role",
		"mode": "managed",
		"change": {"actions": ["create"], "after": {"inline_policy": [{"name": "send", "policy": policy_doc([ses_stmt({})])}]}, "after_unknown": {"inline_policy": [{"policy": false}]}},
	}
	count(ses_warn_on(ses_plan([role]))) == 0
	count(ses_deny_on(ses_plan([role]))) == 0
}

# prior_state: resources the plan leaves unchanged are read from the state
# Terraform refreshed before planning, so a policy that was unknown at its
# first plan is checked on the next one.

state_res(address, type, values) := {"address": address, "mode": "managed", "type": type, "values": values}

state_plan(rcs, root_resources, child_modules) := {
	"configuration": {"provider_config": {}},
	"resource_changes": rcs,
	"prior_state": {"values": {"root_module": {"resources": root_resources, "child_modules": child_modules}}},
}

star_policy := policy_doc([ses_stmt({"Resource": "*"})])

noop_rc(address, type) := {"address": address, "type": type, "mode": "managed", "change": {"actions": ["no-op"]}}

test_ses_prior_state_noop_policy_denied if {
	denies := ses_deny_on(state_plan(
		[noop_rc("aws_iam_role_policy.send", "aws_iam_role_policy")],
		[state_res("aws_iam_role_policy.send", "aws_iam_role_policy", {"policy": star_policy})],
		[],
	))
	some msg in denies
	startswith(msg, "aws_iam_role_policy.send: IAM statement \"Send\" allows SES send on Resource \"*\"")
}

test_ses_prior_state_without_resource_change_denied if {
	some msg in ses_deny_on(state_plan([], [state_res("aws_iam_policy.send", "aws_iam_policy", {"policy": star_policy})], []))
	contains(msg, "aws_iam_policy.send")
}

test_ses_prior_state_child_module_role_inline_policy_denied if {
	role := state_res("module.app.aws_iam_role.app", "aws_iam_role", {"inline_policy": [{"name": "send", "policy": star_policy}]})
	some msg in ses_deny_on(state_plan([], [], [{"address": "module.app", "resources": [role]}]))
	contains(msg, "module.app.aws_iam_role.app inline_policy \"send\"")
}

test_ses_prior_state_replaced_by_fixed_update_passes if {
	fixed := object.union(policy_rc("aws_iam_role_policy", policy_doc([ses_stmt({})])), {"change": {"actions": ["update"], "after": {"policy": policy_doc([ses_stmt({})])}, "after_unknown": {}}})
	count(ses_deny_on(state_plan(
		[fixed],
		[state_res("aws_iam_role_policy.send", "aws_iam_role_policy", {"policy": star_policy})],
		[],
	))) == 0
}

test_ses_prior_state_deleted_policy_passes if {
	gone := {"address": "aws_iam_policy.send", "type": "aws_iam_policy", "mode": "managed", "change": {"actions": ["delete"], "after": null}}
	count(ses_deny_on(state_plan([gone], [state_res("aws_iam_policy.send", "aws_iam_policy", {"policy": star_policy})], []))) == 0
}

test_ses_prior_state_data_source_ignored if {
	ds := {"address": "data.aws_iam_policy.ses", "mode": "data", "type": "aws_iam_policy", "values": {"policy": star_policy}}
	count(ses_deny_on(state_plan([], [ds], []))) == 0
}

test_ses_unknown_then_known_on_next_plan if {
	first := {
		"address": "aws_iam_role_policy.send",
		"type": "aws_iam_role_policy",
		"mode": "managed",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {"policy": true}},
	}
	count(ses_deny_on(ses_plan([first]))) == 0
	some msg in ses_deny_on(state_plan(
		[noop_rc("aws_iam_role_policy.send", "aws_iam_role_policy")],
		[state_res("aws_iam_role_policy.send", "aws_iam_role_policy", {"policy": star_policy})],
		[],
	))
	contains(msg, "aws_iam_role_policy.send")
}

# Attaching an AWS managed policy that allows SES send on every resource.

ses_full := "arn:aws:iam::aws:policy/AmazonSESFullAccess"

lambda_basic := "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

attach_rc(type, values) := {
	"address": sprintf("%s.this", [type]),
	"type": type,
	"mode": "managed",
	"change": {"actions": ["create"], "after": values, "after_unknown": {}},
}

attach_forms(arn) := [
	attach_rc("aws_iam_role_policy_attachment", {"role": "app", "policy_arn": arn}),
	attach_rc("aws_iam_user_policy_attachment", {"user": "app", "policy_arn": arn}),
	attach_rc("aws_iam_group_policy_attachment", {"group": "app", "policy_arn": arn}),
	attach_rc("aws_iam_policy_attachment", {"name": "app", "roles": ["app"], "policy_arn": arn}),
	attach_rc("aws_iam_role_policy_attachments_exclusive", {"role_name": "app", "policy_arns": [lambda_basic, arn]}),
	attach_rc("aws_iam_user_policy_attachments_exclusive", {"user_name": "app", "policy_arns": [arn]}),
	attach_rc("aws_iam_group_policy_attachments_exclusive", {"group_name": "app", "policy_arns": [arn]}),
	attach_rc("aws_iam_role", {"name": "app", "managed_policy_arns": [arn]}),
]

test_ses_managed_policy_every_attachment_form_denied if {
	every rc in attach_forms(ses_full) {
		some msg in ses_deny_on(ses_plan([rc]))
		startswith(msg, sprintf("%s: attaches %s", [rc.address, ses_full]))
	}
}

test_ses_every_listed_managed_policy_denied if {
	every arn in aws_managed_ses_send_policy_arns {
		some msg in ses_deny_on(ses_plan([attach_rc("aws_iam_role_policy_attachment", {"role": "app", "policy_arn": arn})]))
		contains(msg, arn)
	}
}

test_ses_other_managed_policy_attachment_passes if {
	count(ses_deny_on(ses_plan(attach_forms(lambda_basic)))) == 0
}

test_ses_role_without_managed_policy_arns_passes if {
	count(ses_deny_on(ses_plan([attach_rc("aws_iam_role", {"name": "app", "managed_policy_arns": null})]))) == 0
}

test_ses_prior_state_attachment_denied if {
	att := state_res("aws_iam_role_policy_attachment.ses", "aws_iam_role_policy_attachment", {"role": "app", "policy_arn": ses_full})
	some msg in ses_deny_on(state_plan([noop_rc("aws_iam_role_policy_attachment.ses", "aws_iam_role_policy_attachment")], [att], []))
	startswith(msg, "aws_iam_role_policy_attachment.ses: attaches arn:aws:iam::aws:policy/AmazonSESFullAccess")
}

test_ses_unknown_attachment_arn_skipped_with_warning if {
	every pair in [
		["aws_iam_role_policy_attachment", {"policy_arn": true}],
		["aws_iam_role_policy_attachments_exclusive", {"policy_arns": [false, true]}],
		["aws_iam_role", {"managed_policy_arns": [false, true]}],
	] {
		rc := object.union(attach_rc(pair[0], {"name": "app"}), {"change": {"actions": ["create"], "after": {"name": "app"}, "after_unknown": pair[1]}})
		count(ses_deny_on(ses_plan([rc]))) == 0
		some msg in ses_warn_on(ses_plan([rc]))
		startswith(msg, sprintf("%s.this: an attached policy ARN is unknown until apply", [pair[0]]))
	}
}

test_ses_known_attachment_arn_no_warning if {
	count(ses_warn_on(ses_plan(attach_forms(lambda_basic)))) == 0
}

# The approved From list is district data (data.ses_from_addresses, from
# cloud.aws.ses.approved_from_addresses in the environment file).

pinned_plan := ses_plan([policy_rc("aws_iam_role_policy", policy_doc([ses_stmt({})]))])

test_ses_pinned_statement_without_from_list_denied if {
	denies := deny with input as pinned_plan
	some msg in denies
	startswith(msg, "aws_iam_role_policy.send: IAM statement \"Send\" pins ses:FromAddress, but data.ses_from_addresses is missing or empty")
	contains(msg, "cloud.aws.ses.approved_from_addresses")
	count({m | some m in denies; contains(m, "not an approved From address")}) == 0
}

test_ses_pinned_statement_with_from_list_not_present_denied if {
	some msg in deny with input as pinned_plan
		with data.ses_from_addresses as {"present": false, "approved_from_addresses": []}
	contains(msg, "data.ses_from_addresses is missing or empty")
}

test_ses_scope_checks_run_without_from_list if {
	plan := ses_plan([policy_rc("aws_iam_role_policy", policy_doc([ses_stmt({"Resource": "*"})]))])
	some msg in deny with input as plan
	contains(msg, "allows SES send on Resource \"*\"")
}

test_ses_plan_without_send_permission_passes_without_from_list if {
	plan := ses_plan(array.concat(
		[policy_rc("aws_iam_policy", policy_doc([{"Effect": "Allow", "Action": ["s3:GetObject", "ses:GetAccount"], "Resource": "*"}]))],
		attach_forms(lambda_basic),
	))
	count(deny) == 0 with input as plan
}

test_ses_wildcard_list_entry_approves_nothing if {
	listed := {"present": true, "approved_from_addresses": ["*@<district-domain>", "app-alerts@<district-domain>"]}
	stmt := ses_stmt({"Condition": {"StringLike": {"ses:FromAddress": "*@<district-domain>"}}})
	some msg in deny with input as ses_plan([policy_rc("aws_iam_role_policy", policy_doc([stmt]))])
		with data.ses_from_addresses as listed
	contains(msg, "not an approved From address")
}

test_ses_list_entry_compared_lowercase if {
	listed := {"present": true, "approved_from_addresses": ["App-Alerts@<district-domain>"]}
	count(deny) == 0 with input as pinned_plan with data.ses_from_addresses as listed
}
