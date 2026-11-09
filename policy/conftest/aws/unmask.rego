# ABOUTME: logs:Unmask rules for 08-iac.md "Student PII account posture": no student-pii app root grants it, and in the
# ABOUTME: account-baseline root only the break-glass role holds it, with a fixed shape of policies and trust.
package aws

# A policy document grants logs:Unmask when an Allow statement's Action matches
# it, or the statement has a NotAction that does not, under IAM's
# case-insensitive * and ? wildcards. Resource and Condition are not read: an
# Allow that covers the action grants it on something. A document unknown at
# plan time cannot be read here, and the boundary's DenyLogsUnmask still
# covers it. A managed policy never passes, because any principal can
# attach it later. Not waivable through exceptions.yml. acct_baseline_root,
# acct_app_root, acct_cfg, acct_cfg_ok and acct_statements are in
# account_controls.rego.

unmask_list(x) := x if is_array(x)

unmask_list(x) := [x] if is_string(x)

unmask_covered(patterns) if {
	some p in unmask_list(patterns)
	is_string(p)
	glob.match(lower(p), [], "logs:unmask")
}

unmask_statement(st) if {
	st.Effect == "Allow"
	unmask_covered(st.Action)
}

unmask_statement(st) if {
	st.Effect == "Allow"
	is_object(st)
	"NotAction" in object.keys(st)
	not unmask_covered(st.NotAction)
}

unmask_grants_in(policy) if {
	is_string(policy)
	json.is_valid(policy)
	some st in acct_statements(json.unmarshal(policy))
	unmask_statement(st)
}

# No-op counts: reclassifying a root leaves an existing grant unchanged.
unmask_writes := [rc |
	some rc in input.resource_changes
	some action in rc.change.actions
	action in {"create", "update", "no-op"}
]

unmask_name(obj, key) := obj[key] if {
	is_string(obj[key])
	obj[key] != ""
}

# Every IAM policy document the plan creates, updates or keeps, with who holds
# it: desc names the holder for the message, role is the role name when the
# holder is a known role and "" otherwise.
unmask_docs contains {"address": rc.address, "policy": rc.change.after.policy, "desc": desc, "role": role} if {
	some rc in unmask_writes
	rc.type == "aws_iam_role_policy"
	role := object.get(rc.change.after, "role", "")
	desc := unmask_role_desc("an inline policy", rc.change.after, "role")
}

unmask_docs contains {"address": rc.address, "policy": ip.policy, "desc": desc, "role": role} if {
	some rc in unmask_writes
	rc.type == "aws_iam_role"
	some ip in rc.change.after.inline_policy
	role := object.get(rc.change.after, "name", "")
	desc := unmask_role_desc(sprintf("inline_policy %s", [ip.name]), rc.change.after, "name")
}

unmask_docs contains {"address": rc.address, "policy": rc.change.after.policy, "desc": "a managed policy", "role": ""} if {
	some rc in unmask_writes
	rc.type == "aws_iam_policy"
}

unmask_docs contains {"address": rc.address, "policy": rc.change.after.policy, "desc": desc, "role": ""} if {
	some rc in unmask_writes
	some type, key in {"aws_iam_user_policy": "user", "aws_iam_group_policy": "group"}
	rc.type == type
	desc := sprintf("an inline policy on %s %s", [key, object.get(rc.change.after, key, "not known at plan time")])
}

unmask_role_desc(what, after, key) := sprintf("%s on role %s", [what, unmask_name(after, key)])

unmask_role_desc(what, after, key) := sprintf("%s on a role not known at plan time (reference the role's name attribute, not its id)", [what]) if {
	not unmask_name(after, key)
}

unmask_grants := {d | some d in unmask_docs; unmask_grants_in(d.policy)}

unmask_breakglass(d) if {
	acct_cfg_ok
	d.role == acct_cfg.breakglass_role_name
}

deny contains msg if {
	acct_app_root
	some d in unmask_grants
	msg := sprintf("%s: student-pii app root, %s grants logs:Unmask; no app role may unmask student-pii log data, only the account-baseline root's break-glass role (%s)", [d.address, d.desc, posture_rule])
}

deny contains msg if {
	acct_baseline_root
	some d in unmask_grants
	not unmask_breakglass(d)
	msg := sprintf("%s: account-baseline root, %s grants logs:Unmask; only the role named by cloud.aws.student_pii.breakglass_role_name may hold it, through aws_iam_role_policy with role set to that name or that role's inline_policy (%s)", [d.address, d.desc, posture_rule])
}

# Break-glass role content. In the account-baseline root, the role named by
# breakglass_role_name holds only what modules/student-pii-account-baseline
# gives it: inline policies allowing logs:Unmask alone, the AWS-managed
# CloudWatchLogsReadOnlyAccess policy, and a trust that names only account
# root principals and requires the break-glass permission set's IAM Identity
# Center role (ArnLike aws:PrincipalArn), a source identity and a pinned Region.
# Create, update and no-op count. Not waivable. The plan carries no trusted
# account id, so the root of any account passes the principal check.
breakglass_changes(type) := {rc |
	acct_baseline_root
	acct_cfg_ok
	some rc in input.resource_changes
	rc.type == type
	some action in rc.change.actions
	action in {"create", "update", "no-op"}
}

breakglass_roles := {rc |
	some rc in breakglass_changes("aws_iam_role")
	rc.change.after.name == acct_cfg.breakglass_role_name
}

breakglass_doc(policy) := json.unmarshal(policy) if {
	is_string(policy)
	json.is_valid(policy)
}

# Inline policy documents on the role. An empty inline_policy block, which
# removes inline policies added out of band, carries no document.
breakglass_inline contains {"address": rc.address, "desc": "an inline policy", "policy": object.get(rc.change.after, "policy", null)} if {
	some rc in breakglass_changes("aws_iam_role_policy")
	rc.change.after.role == acct_cfg.breakglass_role_name
}

breakglass_inline contains {"address": rc.address, "desc": sprintf("inline_policy %s", [object.get(ip, "name", "")]), "policy": object.get(ip, "policy", null)} if {
	some rc in breakglass_roles
	some ip in rc.change.after.inline_policy
	object.get(ip, "policy", null) != ""
}

breakglass_unmask_action(a) if {
	is_string(a)
	lower(a) == "logs:unmask"
}

# What one Allow statement allows beyond logs:Unmask.
breakglass_extra(st) := ["every action outside its NotAction"] if {
	"NotAction" in object.keys(st)
} else := [sprintf("%v", [a]) | some a in unmask_list(st.Action); not breakglass_unmask_action(a)]

deny contains msg if {
	some p in breakglass_inline
	not breakglass_doc(p.policy)
	msg := sprintf("%s: account-baseline root, %s on break-glass role %s is not known JSON at plan time, so its actions cannot be checked. Build it with jsonencode from values known at plan time (%s)", [p.address, p.desc, acct_cfg.breakglass_role_name, posture_rule])
}

deny contains msg if {
	some p in breakglass_inline
	extra := {x |
		some st in acct_statements(breakglass_doc(p.policy))
		st.Effect == "Allow"
		some x in breakglass_extra(st)
	}
	count(extra) > 0
	msg := sprintf("%s: account-baseline root, %s on break-glass role %s allows %s. Its inline policies may allow only logs:Unmask (%s)", [p.address, p.desc, acct_cfg.breakglass_role_name, concat(", ", sort(extra)), posture_rule])
}

# Managed policies on the role: attachments of either resource type and the
# role's own managed_policy_arns. A policy_arn unknown at plan time is null.
breakglass_attached contains {"address": rc.address, "arn": object.get(rc.change.after, "policy_arn", null)} if {
	some rc in breakglass_changes("aws_iam_role_policy_attachment")
	rc.change.after.role == acct_cfg.breakglass_role_name
}

breakglass_attached contains {"address": rc.address, "arn": object.get(rc.change.after, "policy_arn", null)} if {
	some rc in breakglass_changes("aws_iam_policy_attachment")
	acct_cfg.breakglass_role_name in rc.change.after.roles
}

breakglass_attached contains {"address": rc.address, "arn": arn} if {
	some rc in breakglass_roles
	some arn in rc.change.after.managed_policy_arns
}

breakglass_read_only(arn) if {
	is_string(arn)
	regex.match(`^arn:aws[a-z-]*:iam::aws:policy/CloudWatchLogsReadOnlyAccess$`, arn)
}

breakglass_arn_label(arn) := arn if is_string(arn)

else := "a policy not known at plan time"

deny contains msg if {
	some a in breakglass_attached
	not breakglass_read_only(a.arn)
	msg := sprintf("%s: account-baseline root, attaches %s to break-glass role %s. The only managed policy it may hold is arn:<partition>:iam::aws:policy/CloudWatchLogsReadOnlyAccess (%s)", [a.address, breakglass_arn_label(a.arn), acct_cfg.breakglass_role_name, posture_rule])
}

breakglass_trust(rc) := breakglass_doc(rc.change.after.assume_role_policy)

deny contains msg if {
	some rc in breakglass_roles
	not breakglass_trust(rc)
	msg := sprintf("%s: account-baseline root, the assume_role_policy of break-glass role %s is not known JSON at plan time, so its trust cannot be checked. Build it with jsonencode from values known at plan time (%s)", [rc.address, acct_cfg.breakglass_role_name, posture_rule])
}

breakglass_account_root(type, id) if {
	type == "AWS"
	is_string(id)
	regex.match(`^arn:aws[a-z-]*:iam::\d{12}:root$`, id)
}

# Principals of one Allow statement that are not an AWS account root.
breakglass_principals(st) := ["*"] if {
	st.Principal == "*"
} else := ["NotPrincipal"] if {
	"NotPrincipal" in object.keys(st)
} else := [sprintf("%s %v", [type, id]) |
	some type, ids in st.Principal
	some id in unmask_list(ids)
	not breakglass_account_root(type, id)
]

deny contains msg if {
	some rc in breakglass_roles
	bad := {p |
		some st in acct_statements(breakglass_trust(rc))
		st.Effect == "Allow"
		some p in breakglass_principals(st)
	}
	count(bad) > 0
	msg := sprintf("%s: account-baseline root, the trust policy of break-glass role %s names %s. It may name only AWS account root principals, arn:<partition>:iam::<account-id>:root (%s)", [rc.address, acct_cfg.breakglass_role_name, concat(", ", sort(bad)), posture_rule])
}

# The conditions on every Allow statement of the trust, as the module sets
# them: operator, key and the accepted value. A string must match exactly,
# null accepts any Region, and permission_set_role accepts only the module's
# pattern for the break-glass permission set's Identity Center role.
breakglass_conditions := {
	"ArnLike aws:PrincipalArn on the break-glass permission set's role": ["ArnLike", "aws:PrincipalArn", {"permission_set_role": true}],
	`Null sts:SourceIdentity = "false"`: ["Null", "sts:SourceIdentity", "false"],
	"StringEquals aws:RequestedRegion": ["StringEquals", "aws:RequestedRegion", null],
}

breakglass_condition_value(v, want) if {
	is_string(want)
	v == want
}

# arn:<partition>:iam::<account-id>:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_<name>_*
# Any other wildcard placement could match a role outside that permission set.
breakglass_condition_value(v, {"permission_set_role": true}) if {
	is_string(v)
	suffix := sprintf("/AWSReservedSSO_%s_*", [acct_cfg.breakglass_permission_set_name])
	endswith(v, suffix)
	head := substring(v, 0, count(v) - count(suffix))
	regex.match(`^arn:aws[a-z-]*:iam::\d{12}:role/aws-reserved/sso\.amazonaws\.com\*$`, head)
}

breakglass_condition_value(v, null) if {
	is_string(v)
	v != ""
}

breakglass_condition_met(st, c) if {
	values := unmask_list(st.Condition[c[0]][c[1]])
	count(values) > 0
	every v in values {
		breakglass_condition_value(v, c[2])
	}
}

deny contains msg if {
	some rc in breakglass_roles
	some i, st in acct_statements(breakglass_trust(rc))
	st.Effect == "Allow"
	missing := sort([label | some label, c in breakglass_conditions; not breakglass_condition_met(st, c)])
	count(missing) > 0
	msg := sprintf("%s: account-baseline root, trust statement %s of break-glass role %s lacks %s. Every Allow statement needs all three conditions (%s)", [rc.address, object.get(st, "Sid", sprintf("%d", [i])), acct_cfg.breakglass_role_name, concat(", ", missing), posture_rule])
}
