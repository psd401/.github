# ABOUTME: Tests for unmask.rego: no IAM policy document in a student-pii app root grants logs:Unmask, and in
# ABOUTME: the account-baseline root only an inline policy on the break-glass role does.
package aws

# acct_baseline_marker, acct_plan and data.acct_student_pii_account come from
# account_controls_test.rego and its fixture. pii_marker comes from
# student_pii_logs_test.rego.

unmask_allow(action) := {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]}

unmask_rc(address, type, after, after_unknown) := {
	"address": address,
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": after_unknown},
}

unmask_role_policy(role, doc) := unmask_rc("aws_iam_role_policy.grant", "aws_iam_role_policy", {"name": "grant", "role": role, "policy": json.marshal(doc)}, {})

# Findings that name logs:Unmask under the account-posture rule id.
unmask_findings(msgs) := {m |
	some m in msgs
	contains(m, "grants logs:Unmask")
	endswith(m, "(08-iac.md#student-pii-account-posture)")
}

unmask_app_findings(rc) := findings if {
	findings := unmask_findings(deny) with input as acct_plan([pii_marker, rc])
}

unmask_baseline_findings(rc) := findings if {
	findings := unmask_findings(deny) with input as acct_plan([acct_baseline_marker, rc])
		with data.student_pii_account as data.acct_student_pii_account
}

test_app_root_unmask_grant_denied if {
	findings := unmask_app_findings(unmask_role_policy("app-runtime", unmask_allow("logs:Unmask")))
	count(findings) == 1
	some m in findings
	startswith(m, "aws_iam_role_policy.grant: student-pii app root, an inline policy on role app-runtime grants logs:Unmask")
}

test_app_root_wildcards_that_cover_unmask_denied if {
	every action in ["logs:*", "logs:Un*", "*", "LOGS:UNMASK", "logs:Unmas?", ["s3:GetObject", "*:Unmask"]] {
		count(unmask_app_findings(unmask_role_policy("app-runtime", unmask_allow(action)))) == 1
	}
}

test_app_root_not_action_that_leaves_unmask_allowed_denied if {
	doc := {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "NotAction": ["s3:*", "logs:Get*"], "Resource": "*"}]}
	count(unmask_app_findings(unmask_role_policy("app-runtime", doc))) == 1
}

test_app_root_policies_without_an_unmask_grant_pass if {
	every doc in [
		unmask_allow("logs:GetLogEvents"),
		unmask_allow(["logs:Get*", "logs:PutLogEvents", "logs:CreateLogStream"]),
		{"Statement": [{"Effect": "Deny", "Action": "logs:*", "Resource": "*"}]},
		{"Statement": [{"Effect": "Allow", "NotAction": "logs:*", "Resource": "*"}]},
		{"Statement": [{"Effect": "Allow", "NotAction": ["s3:*", "logs:Unmask"], "Resource": "*"}]},
	] {
		count(unmask_app_findings(unmask_role_policy("app-runtime", doc))) == 0
	}
}

test_every_iam_policy_resource_type_checked if {
	doc := json.marshal({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "logs:Unmask", "Resource": "*"}})
	every rc in [
		unmask_rc("aws_iam_policy.logs", "aws_iam_policy", {"name": "logs", "policy": doc}, {}),
		unmask_rc("aws_iam_role.app", "aws_iam_role", {"name": "app-runtime", "inline_policy": [{"name": "logs", "policy": doc}]}, {}),
		unmask_rc("aws_iam_user_policy.logs", "aws_iam_user_policy", {"name": "logs", "user": "someone", "policy": doc}, {}),
		unmask_rc("aws_iam_group_policy.logs", "aws_iam_group_policy", {"name": "logs", "group": "admins", "policy": doc}, {}),
	] {
		findings := unmask_app_findings(rc)
		count(findings) == 1
		some m in findings
		startswith(m, sprintf("%s: student-pii app root", [rc.address]))
	}
}

# No app role is the break-glass role (CONTRACT section 8), so its name earns
# no exemption outside the account-baseline root.
test_app_root_grant_to_the_breakglass_name_still_denied if {
	findings := unmask_findings(deny) with input as acct_plan([pii_marker, unmask_role_policy("district-breakglass-unmask", unmask_allow("logs:Unmask"))])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 1
}

test_baseline_root_breakglass_inline_grants_pass if {
	doc := unmask_allow("logs:Unmask")
	count(unmask_baseline_findings(unmask_role_policy("district-breakglass-unmask", doc))) == 0
	inline := unmask_rc("aws_iam_role.breakglass", "aws_iam_role", {"name": "district-breakglass-unmask", "inline_policy": [{"name": "unmask", "policy": json.marshal(doc)}]}, {})
	count(unmask_baseline_findings(inline)) == 0
}

test_baseline_root_grant_to_any_other_principal_denied if {
	doc := json.marshal(unmask_allow("logs:*"))
	every rc_and_needle in [
		[unmask_role_policy("ops-admin", unmask_allow("logs:*")), "an inline policy on role ops-admin"],
		[unmask_rc("aws_iam_policy.logs", "aws_iam_policy", {"name": "logs", "policy": doc}, {}), "a managed policy"],
		[unmask_rc("aws_iam_role.ops", "aws_iam_role", {"name": "ops-admin", "inline_policy": [{"name": "logs", "policy": doc}]}, {}), "inline_policy logs on role ops-admin"],
		[unmask_rc("aws_iam_user_policy.logs", "aws_iam_user_policy", {"name": "logs", "user": "someone", "policy": doc}, {}), "an inline policy on user someone"],
	] {
		findings := unmask_baseline_findings(rc_and_needle[0])
		count(findings) == 1
		some m in findings
		startswith(m, sprintf("%s: account-baseline root, %s grants logs:Unmask", [rc_and_needle[0].address, rc_and_needle[1]]))
	}
}

test_baseline_root_grant_to_a_role_unknown_at_plan_denied if {
	rc := unmask_rc("aws_iam_role_policy.grant", "aws_iam_role_policy", {"name": "grant", "policy": json.marshal(unmask_allow("logs:Unmask"))}, {"role": true})
	findings := unmask_baseline_findings(rc)
	count(findings) == 1
	some m in findings
	contains(m, "a role not known at plan time")
}

test_unmask_rule_ignores_exceptions_entries if {
	rc := unmask_role_policy("app-runtime", unmask_allow("logs:Unmask"))
	findings := unmask_findings(deny) with input as acct_plan([pii_marker, rc])
		with data.exceptions as [
			pii_entry("unmask-1", rc.address),
			object.union(pii_entry("unmask-2", rc.address), {"standard": "08-iac.md#student-pii-account-posture"}),
		]
	count(findings) == 1
}

# A reclassified root leaves an existing grant no-op.
test_app_root_existing_unmask_grant_no_op_denied if {
	findings := unmask_app_findings(no_op(unmask_role_policy("app-runtime", unmask_allow("logs:*"))))
	count(findings) == 1
	some m in findings
	startswith(m, "aws_iam_role_policy.grant: student-pii app root, an inline policy on role app-runtime grants logs:Unmask")
}

# Break-glass role content in the account-baseline root, against the shape
# modules/student-pii-account-baseline/main.tf plans (fixture acct_plan_baseline).
bg_name := "district-breakglass-unmask"

bg_trust := {
	"Sid": "PermissionSetAndSourceIdentityRequired",
	"Effect": "Allow",
	"Principal": {"AWS": "arn:aws:iam::111111111111:root"},
	"Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
	"Condition": {
		"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_StudentPiiBreakGlass_*"},
		"Null": {"sts:SourceIdentity": "false"},
		"StringEquals": {"aws:RequestedRegion": "us-west-2"},
	},
}

bg_role(statement, actions) := {
	"address": "aws_iam_role.breakglass",
	"type": "aws_iam_role",
	"change": {"actions": actions, "after_unknown": {}, "after": {
		"name": bg_name,
		"assume_role_policy": json.marshal({"Version": "2012-10-17", "Statement": [statement]}),
		"tags_all": {"psd:data-classification": "internal", "psd:root": "account-baseline"},
	}},
}

bg_attachment(arn) := unmask_rc("aws_iam_role_policy_attachment.read", "aws_iam_role_policy_attachment", {"role": bg_name, "policy_arn": arn}, {})

bg_messages(msgs) := {m |
	some m in msgs
	contains(m, sprintf("break-glass role %s", [bg_name]))
	endswith(m, "(08-iac.md#student-pii-account-posture)")
}

bg_findings(rcs) := findings if {
	findings := bg_messages(deny) with input as acct_plan(rcs)
		with data.student_pii_account as data.acct_student_pii_account
}

test_baseline_breakglass_role_in_the_module_shape_passes if {
	count(bg_findings(data.acct_plan_baseline.resource_changes)) == 0
	count(bg_findings([bg_role(bg_trust, ["create"]), bg_attachment("arn:aws-us-gov:iam::aws:policy/CloudWatchLogsReadOnlyAccess")])) == 0
}

test_baseline_breakglass_inline_policy_allowing_more_than_unmask_denied if {
	role := bg_role(bg_trust, ["create"])
	extra := unmask_allow(["logs:Unmask", "logs:DeleteLogGroup"])
	inline_role := json.patch(role, [{"op": "add", "path": "/change/after/inline_policy", "value": [{"name": "extra", "policy": json.marshal(extra)}]}])
	not_action := {"Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}
	unknown := unmask_rc("aws_iam_role_policy.grant", "aws_iam_role_policy", {"name": "grant", "role": bg_name}, {"policy": true})
	every rcs_and_needle in [
		[[role, unmask_role_policy(bg_name, extra)], "aws_iam_role_policy.grant: account-baseline root, an inline policy on break-glass role district-breakglass-unmask allows logs:DeleteLogGroup."],
		[[inline_role], "aws_iam_role.breakglass: account-baseline root, inline_policy extra on break-glass role district-breakglass-unmask allows logs:DeleteLogGroup."],
		[[role, unmask_role_policy(bg_name, not_action)], "an inline policy on break-glass role district-breakglass-unmask allows every action outside its NotAction."],
		[[role, unknown], "an inline policy on break-glass role district-breakglass-unmask is not known JSON at plan time"],
	] {
		findings := bg_findings(rcs_and_needle[0])
		count(findings) == 1
		some m in findings
		contains(m, rcs_and_needle[1])
	}
}

test_baseline_breakglass_managed_policy_other_than_read_only_denied if {
	role := bg_role(bg_trust, ["create"])
	unknown := unmask_rc("aws_iam_role_policy_attachment.read", "aws_iam_role_policy_attachment", {"role": bg_name}, {"policy_arn": true})
	shared := unmask_rc("aws_iam_policy_attachment.ops", "aws_iam_policy_attachment", {"name": "ops", "roles": ["ops-admin", bg_name], "policy_arn": "arn:aws:iam::111111111111:policy/ops"}, {})
	managed_arns := json.patch(role, [{"op": "add", "path": "/change/after/managed_policy_arns", "value": ["arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess", "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"]}])
	every rcs_and_needle in [
		[[role, bg_attachment("arn:aws:iam::aws:policy/AdministratorAccess")], "aws_iam_role_policy_attachment.read: account-baseline root, attaches arn:aws:iam::aws:policy/AdministratorAccess to break-glass role"],
		[[role, unknown], "aws_iam_role_policy_attachment.read: account-baseline root, attaches a policy not known at plan time to break-glass role"],
		[[role, shared], "aws_iam_policy_attachment.ops: account-baseline root, attaches arn:aws:iam::111111111111:policy/ops to break-glass role"],
		[[managed_arns], "aws_iam_role.breakglass: account-baseline root, attaches arn:aws:iam::aws:policy/CloudWatchLogsFullAccess to break-glass role"],
	] {
		findings := bg_findings(rcs_and_needle[0])
		count(findings) == 1
		some m in findings
		startswith(m, rcs_and_needle[1])
	}
}

test_baseline_breakglass_trust_unknown_at_plan_denied if {
	role := json.patch(bg_role(bg_trust, ["create"]), [
		{"op": "remove", "path": "/change/after/assume_role_policy"},
		{"op": "add", "path": "/change/after_unknown/assume_role_policy", "value": true},
	])
	findings := bg_findings([role])
	count(findings) == 1
	some m in findings
	startswith(m, "aws_iam_role.breakglass: account-baseline root, the assume_role_policy of break-glass role district-breakglass-unmask is not known JSON at plan time")
}

test_baseline_breakglass_trust_naming_anything_but_an_account_root_denied if {
	every principal_and_label in [
		[{"Service": "ec2.amazonaws.com"}, "Service ec2.amazonaws.com"],
		[{"Federated": "arn:aws:iam::111111111111:saml-provider/idp"}, "Federated arn:aws:iam::111111111111:saml-provider/idp"],
		["*", "*"],
		[{"AWS": "*"}, "AWS *"],
		[{"AWS": ["arn:aws:iam::111111111111:root", "arn:aws:iam::111111111111:role/ops"]}, "AWS arn:aws:iam::111111111111:role/ops"],
	] {
		st := json.patch(bg_trust, [{"op": "replace", "path": "/Principal", "value": principal_and_label[0]}])
		findings := bg_findings([bg_role(st, ["create"])])
		count(findings) == 1
		some m in findings
		startswith(m, sprintf("aws_iam_role.breakglass: account-baseline root, the trust policy of break-glass role district-breakglass-unmask names %s.", [principal_and_label[1]]))
	}
}

test_baseline_breakglass_trust_missing_a_required_condition_denied if {
	every op_and_label in [
		["ArnLike", "ArnLike aws:PrincipalArn on the break-glass permission set's role"],
		["Null", `Null sts:SourceIdentity = "false"`],
		["StringEquals", "StringEquals aws:RequestedRegion"],
	] {
		st := json.patch(bg_trust, [{"op": "remove", "path": sprintf("/Condition/%s", [op_and_label[0]])}])
		findings := bg_findings([bg_role(st, ["create"])])
		count(findings) == 1
		some m in findings
		startswith(m, sprintf("aws_iam_role.breakglass: account-baseline root, trust statement PermissionSetAndSourceIdentityRequired of break-glass role district-breakglass-unmask lacks %s.", [op_and_label[1]]))
	}
}

# Any other permission set, a broader wildcard, or a pattern that also matches
# a longer permission set name does not count as the break-glass caller.
test_baseline_breakglass_trust_with_another_caller_pattern_denied if {
	every arn in [
		"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_AdministratorAccess_*",
		"arn:aws:iam::111111111111:role/*",
		"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_StudentPiiBreakGlass*",
		"arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_StudentPiiBreakGlass_*",
		"arn:aws:iam::111111111111:role/ops/AWSReservedSSO_StudentPiiBreakGlass_*",
	] {
		st := json.patch(bg_trust, [{"op": "replace", "path": "/Condition/ArnLike/aws:PrincipalArn", "value": arn}])
		some m in bg_findings([bg_role(st, ["create"])])
		contains(m, "lacks ArnLike aws:PrincipalArn on the break-glass permission set's role.")
	}
	us_gov := json.patch(bg_trust, [{"op": "replace", "path": "/Condition/ArnLike/aws:PrincipalArn", "value": "arn:aws-us-gov:iam::111111111111:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_StudentPiiBreakGlass_*"}])
	count(bg_findings([bg_role(us_gov, ["create"])])) == 0
}

test_baseline_existing_breakglass_role_checked_and_not_waivable if {
	st := json.patch(bg_trust, [{"op": "replace", "path": "/Principal", "value": {"Service": "lambda.amazonaws.com"}}])
	role := bg_role(st, ["no-op"])
	findings := bg_findings([role]) with data.exceptions as [
		pii_entry("bg-1", role.address),
		object.union(pii_entry("bg-2", role.address), {"standard": "08-iac.md#student-pii-account-posture"}),
	]
	count(findings) == 1
	some m in findings
	contains(m, "names Service lambda.amazonaws.com.")
}

test_baseline_other_roles_not_held_to_the_breakglass_shape if {
	st := json.patch(bg_trust, [{"op": "replace", "path": "/Principal", "value": {"Service": "lambda.amazonaws.com"}}])
	ops := json.patch(bg_role(st, ["create"]), [
		{"op": "replace", "path": "/address", "value": "aws_iam_role.ops"},
		{"op": "replace", "path": "/change/after/name", "value": "ops-admin"},
	])
	admin := unmask_rc("aws_iam_role_policy_attachment.ops", "aws_iam_role_policy_attachment", {"role": "ops-admin", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, {})
	msgs := deny with input as acct_plan([bg_role(bg_trust, ["create"]), ops, admin])
		with data.student_pii_account as data.acct_student_pii_account
	not contains(concat("\n", msgs), "aws_iam_role.ops")
	not contains(concat("\n", msgs), "aws_iam_role_policy_attachment.ops")
}
