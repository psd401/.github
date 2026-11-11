# ABOUTME: 17-email-sending.md rules 3 and 9: IAM grants of SES send are scoped to ARNs and pin ses:FromAddress
# ABOUTME: to the environment file's approved list; broad AWS managed policies that allow SES send are never attached.
package aws

# 17-email-sending.md rule 9 (least-privilege send permissions) and rule 3's
# From-address check (Kris, approved as conftest rules 2026-11-09). For every
# IAM policy document the plan creates or updates, an Allow statement that
# grants an SES send action:
#   1. never has Resource "*" (or NotResource, which allows every other ARN);
#   2. pins ses:FromAddress with a StringEquals/StringLike-family condition
#      (plain, IgnoreCase, ForAllValues: or ForAnyValue:; never ...IfExists,
#      which passes when the key is missing);
#   3. pins only addresses in approved_ses_from_addresses, compared
#      lowercase. A wildcard value such as "*@<district-domain>" is not in
#      the list, so it is denied.
#
# The approved list is district data: data.ses_from_addresses, which
# scripts/iac/resolve_env_file.py --ses-out derives in the plan job from
# cloud.aws.ses.approved_from_addresses in the environment file (present,
# approved_from_addresses). A statement that pins ses:FromAddress is denied
# when that data is missing, present is false or the list is empty. A plan
# that grants no SES send needs no list. Not waivable through exceptions.yml:
# no rule here consults an exception helper.
#
# Documents read, from resources the plan creates or updates and, through
# prior_state, from those it leaves unchanged: the `policy` attribute of
# aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy and
# aws_iam_group_policy, and each inline_policy block's `policy` on
# aws_iam_role. A document that is unknown until apply
# (after_unknown.policy = true, or an aws_iam_role whose
# one inline_policy block's after_unknown policy is true; for example one
# interpolating a resource ARN created in the same plan) cannot be read, so
# it is skipped and reported as a warn, which does not fail the job; the next
# plan reads its applied JSON from prior_state and checks it then.
#
# Attaching an AWS managed policy that grants SES send on every resource
# (ses_managed_send_policies.rego) is denied in every attachment form.
#
# An action is a send action when an Action pattern (IAM's * and ? wildcards,
# case-insensitive) matches one of ses_send_actions, so "ses:*", "ses:Send*"
# and "*" all count. An Allow with NotAction counts unless NotAction excludes
# every send action.

ses_send_actions := {
	"ses:sendemail",
	"ses:sendrawemail",
	"ses:sendtemplatedemail",
	"ses:sendbulkemail",
	"ses:sendbulktemplatedemail",
}

iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

ses_from_operators := {
	"stringequals",
	"stringequalsignorecase",
	"stringlike",
	"forallvalues:stringequals",
	"forallvalues:stringequalsignorecase",
	"forallvalues:stringlike",
	"foranyvalue:stringequals",
	"foranyvalue:stringequalsignorecase",
	"foranyvalue:stringlike",
}

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

ses_cfg := data.ses_from_addresses

# Lowercased. An entry holding an IAM wildcard (* or ?) is dropped, since it
# would approve a StringLike pin of that same pattern; the environment-file
# schema rejects one too.
approved_ses_from_addresses := {lower(a) |
	ses_cfg.present == true
	some a in ses_cfg.approved_from_addresses
	is_string(a)
	not regex.match(`[*?]`, a)
}

ses_cfg_ok if count(approved_ses_from_addresses) > 0

iam_policy_changes := [rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	some action in rc.change.actions
	action in {"create", "update"}
]

changing_actions := {"create", "update", "delete"}

changing_addresses := {rc.address |
	some rc in input.resource_changes
	some action in rc.change.actions
	action in changing_actions
}

# Every managed resource as {"address", "type", "values"}: its planned values
# when this plan creates or updates it, else its prior_state values when the
# plan leaves it as it is (no-op, or no resource_changes entry at all). A
# policy unknown at the plan that creates it is read from prior_state on the
# next plan, once its JSON is known. A resource this plan only deletes is
# read from neither.
iam_resources contains {"address": rc.address, "type": rc.type, "values": rc.change.after} if {
	some rc in iam_policy_changes
	is_object(rc.change.after)
}

iam_resources contains {"address": r.address, "type": r.type, "values": r.values} if {
	walk(input.prior_state.values, [path, r])
	count(path) >= 2
	path[count(path) - 2] == "resources"
	r.mode == "managed"
	not r.address in changing_addresses
}

# {"where": <address>, "policy": <JSON string>} for every readable document.
iam_policy_docs contains {"where": r.address, "policy": r.values.policy} if {
	some r in iam_resources
	r.type in iam_policy_types
	is_string(r.values.policy)
}

iam_policy_docs contains {"where": sprintf("%s inline_policy %q", [r.address, ip.name]), "policy": ip.policy} if {
	some r in iam_resources
	r.type == "aws_iam_role"
	some ip in r.values.inline_policy
	is_string(ip.policy)
	ip.policy != ""
}

ses_send_statements contains [doc.where, i, stmt] if {
	some doc in iam_policy_docs
	json.is_valid(doc.policy)
	parsed := json.unmarshal(doc.policy)
	some i, stmt in as_list(parsed.Statement)
	stmt.Effect == "Allow"
	grants_ses_send(stmt)
}

action_matches(patterns, action) if {
	some p in as_list(patterns)
	is_string(p)
	glob.match(lower(p), null, action)
}

grants_ses_send(stmt) if {
	some a in ses_send_actions
	action_matches(stmt.Action, a)
}

grants_ses_send(stmt) if {
	stmt.NotAction
	some a in ses_send_actions
	not action_matches(stmt.NotAction, a)
}

stmt_label(i, stmt) := sprintf("statement %q", [stmt.Sid]) if {
	is_string(stmt.Sid)
	stmt.Sid != ""
} else := sprintf("statement %d", [i])

ses_from_values(stmt) := [v |
	some op, cond in stmt.Condition
	lower(op) in ses_from_operators
	is_object(cond)
	some key, vals in cond
	lower(key) == "ses:fromaddress"
	some v in as_list(vals)
	is_string(v)
]

deny contains msg if {
	some [where, i, stmt] in ses_send_statements
	"*" in as_list(stmt.Resource)
	msg := sprintf("%s: IAM %s allows SES send on Resource \"*\"; scope it to the shared identity's ARN (or the app's own subdomain identity) and the app's own configuration set ARNs (17-email-sending.md rule 9)", [where, stmt_label(i, stmt)])
}

deny contains msg if {
	some [where, i, stmt] in ses_send_statements
	stmt.NotResource
	msg := sprintf("%s: IAM %s allows SES send with NotResource, which grants every other ARN; list the identity and configuration set ARNs in Resource instead (17-email-sending.md rule 9)", [where, stmt_label(i, stmt)])
}

deny contains msg if {
	some [where, i, stmt] in ses_send_statements
	count(ses_from_values(stmt)) == 0
	msg := sprintf("%s: IAM %s allows SES send with no ses:FromAddress condition; pin the app's From address(es) with StringEquals (17-email-sending.md rules 3 and 9)", [where, stmt_label(i, stmt)])
}

deny contains msg if {
	some [where, i, stmt] in ses_send_statements
	count(ses_from_values(stmt)) > 0
	not ses_cfg_ok
	msg := sprintf("%s: IAM %s pins ses:FromAddress, but data.ses_from_addresses is missing or empty, so the pinned address cannot be checked; the plan job derives it from cloud.aws.ses.approved_from_addresses in the environment file (17-email-sending.md rules 3 and 9)", [where, stmt_label(i, stmt)])
}

deny contains msg if {
	some [where, i, stmt] in ses_send_statements
	ses_cfg_ok
	unapproved := {v |
		some v in ses_from_values(stmt)
		not lower(v) in approved_ses_from_addresses
	}
	count(unapproved) > 0
	msg := sprintf("%s: IAM %s pins ses:FromAddress to %v, not an approved From address; an app sends only from its own app mail group or an alias on it, and adding one to the approved list is a change to cloud.aws.ses.approved_from_addresses in the environment file (17-email-sending.md rules 3 and 9)", [where, stmt_label(i, stmt), unapproved])
}

warn contains msg if {
	some rc in iam_policy_changes
	rc.type in iam_policy_types
	rc.change.after_unknown.policy == true
	msg := sprintf("%s: policy is unknown until apply, so its SES send permissions (17-email-sending.md rule 9) were not checked; review it by hand", [rc.address])
}

# aws_iam_role: one inline_policy block's policy unknown. inline_policy and
# managed_policy_arns are also computed, so the provider marks the whole
# attribute unknown (true) on every role it creates, set or not (hashicorp/aws
# 6.20.0, checked with `tofu show -json` 2026-11-09); that shape is not
# warned on, or every new role would warn. The next plan reads it from
# prior_state.
inline_policy_unknown(rc) if {
	some ip in rc.change.after_unknown.inline_policy
	ip.policy == true
}

warn contains msg if {
	some rc in iam_policy_changes
	rc.type == "aws_iam_role"
	inline_policy_unknown(rc)
	msg := sprintf("%s: an inline_policy is unknown until apply, so its SES send permissions (17-email-sending.md rule 9) were not checked; review it by hand", [rc.address])
}

# Attachment forms (hashicorp/aws resource docs, read 2026-11-09): one ARN in
# policy_arn, or a list in policy_arns / managed_policy_arns.
attached_policy_arns(r) := [r.values.policy_arn] if {
	r.type in {
		"aws_iam_role_policy_attachment",
		"aws_iam_user_policy_attachment",
		"aws_iam_group_policy_attachment",
		"aws_iam_policy_attachment",
	}
}

attached_policy_arns(r) := as_list(r.values.policy_arns) if {
	r.type in {
		"aws_iam_role_policy_attachments_exclusive",
		"aws_iam_user_policy_attachments_exclusive",
		"aws_iam_group_policy_attachments_exclusive",
	}
}

attached_policy_arns(r) := as_list(r.values.managed_policy_arns) if {
	r.type == "aws_iam_role"
	r.values.managed_policy_arns != null
}

deny contains msg if {
	some r in iam_resources
	some arn in attached_policy_arns(r)
	arn in aws_managed_ses_send_policy_arns
	msg := sprintf("%s: attaches %s, an AWS managed policy that allows SES send on Resource \"*\" with no ses:FromAddress condition; write a policy scoped to the identity and configuration set ARNs with the app's From address pinned (17-email-sending.md rule 9)", [r.address, arn])
}

# An attachment whose ARN is unknown at plan (for example from a data source
# whose inputs are unknown) can't be compared with the list: warn, as for an
# unknown document. The next plan reads the applied ARN from prior_state.
attachment_types := {
	"aws_iam_role_policy_attachment",
	"aws_iam_user_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_policy_attachment",
	"aws_iam_role_policy_attachments_exclusive",
	"aws_iam_user_policy_attachments_exclusive",
	"aws_iam_group_policy_attachments_exclusive",
	"aws_iam_role",
}

unknown_arn_attr(u) if u == true

unknown_arn_attr(u) if {
	is_array(u)
	true in u
}

attachment_arn_unknown(rc) if {
	rc.type != "aws_iam_role"
	some attr in ["policy_arn", "policy_arns"]
	unknown_arn_attr(rc.change.after_unknown[attr])
}

# aws_iam_role: only one listed ARN unknown; the whole attribute is unknown on
# every new role (see inline_policy_unknown).
attachment_arn_unknown(rc) if {
	rc.type == "aws_iam_role"
	true in rc.change.after_unknown.managed_policy_arns
}

warn contains msg if {
	some rc in iam_policy_changes
	rc.type in attachment_types
	attachment_arn_unknown(rc)
	msg := sprintf("%s: an attached policy ARN is unknown until apply, so it was not checked against the AWS managed policies that allow SES send (17-email-sending.md rule 9); review it by hand", [rc.address])
}
