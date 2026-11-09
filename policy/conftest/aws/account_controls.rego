# ABOUTME: Account data protection policy rules for 08-iac.md "Student PII account posture": the baseline root's
# ABOUTME: policy lists every required identifier, and no student-pii app root creates, updates or deletes it.
package aws

# The account-baseline root is the root whose default_tags set psd:root =
# account-baseline and psd:data-classification = internal
# (templates/account-baseline/providers.tf). It owns the account-level
# controls. A student-pii app root is a student-pii root (student_pii_logs.rego)
# that is not the baseline root.
#
# default_tags put the tag on every resource that has tags_all, so the plan is
# the baseline root only when at least one resource change carries it and no
# resource change contradicts it. A change contradicts it when its tags_all is
# known and lacks psd:root = account-baseline, when its tags_all sets
# psd:data-classification = student-pii, or when its tags_all, or either of
# those two tags in it, is not known at plan time. One tagged resource in an
# app root does not turn the app-root denies off, and neither does a
# student-pii root that tags every resource. A plan that carries the tag and
# also has a contradicting change gets its own deny. Unless it is tagged
# student-pii it is otherwise neither root, and no account rule would judge
# it. A resource with no tags_all (aws_cloudwatch_log_account_policy, IAM role
# policies) counts neither way. A change is judged by change.after, or by
# change.before for a delete (after null), so deleting a resource without the
# tag still counts. A no-op change carries the current tags_all in after and
# counts like any other.
#
# data.student_pii_account is cloud.aws.student_pii from the environment file,
# reduced by scripts/iac/resolve_env_file.py --student-pii-out to what these
# rules compare against: present, breakglass_role_name,
# breakglass_permission_set_name, managed_identifiers (schema default
# applied) and custom_identifier_names.
# The baseline root fails closed without it. Not waivable through
# exceptions.yml: no rule here consults an exception helper.

posture_rule := "08-iac.md#student-pii-account-posture"

acct_root_tag_state(rc) := rc.change.after if is_object(rc.change.after)

acct_root_tag_state(rc) := rc.change.before if {
	rc.change.after == null
	is_object(rc.change.before)
}

acct_root_tags(rc) := tags if {
	tags := acct_root_tag_state(rc).tags_all
	is_object(tags)
}

# terraform show -json marks a wholly unknown tags_all as after_unknown.tags_all
# = true, and one unknown value as after_unknown.tags_all.<key> = true. Only
# the two tags these rules read count.
acct_root_tags_unknown(rc) if {
	is_object(rc.change.after)
	rc.change.after_unknown.tags_all == true
}

acct_root_tags_unknown(rc) if {
	is_object(rc.change.after)
	some key in ["psd:root", "psd:data-classification"]
	rc.change.after_unknown.tags_all[key] == true
}

acct_root_claims := sort({rc.address |
	some rc in input.resource_changes
	acct_root_tags(rc)["psd:root"] == "account-baseline"
})

# One reason per resource change that contradicts the claim.
acct_root_conflict contains sprintf("%s does not carry it", [rc.address]) if {
	some rc in input.resource_changes
	tags := acct_root_tags(rc)
	object.get(tags, "psd:root", null) != "account-baseline"
	not acct_root_tags_unknown(rc)
}

acct_root_conflict contains sprintf("%s has tags_all values not known at plan time", [rc.address]) if {
	some rc in input.resource_changes
	acct_root_tags_unknown(rc)
}

acct_root_conflict contains sprintf("%s is tagged psd:data-classification = student-pii", [rc.address]) if {
	some rc in input.resource_changes
	acct_root_tags(rc)["psd:data-classification"] == "student-pii"
}

acct_root_conflicts := sort(acct_root_conflict)

acct_baseline_root if {
	count(acct_root_claims) > 0
	count(acct_root_conflicts) == 0
}

acct_app_root if {
	student_pii_root
	not acct_baseline_root
}

# The first five items of a sorted list, and a count of the rest.
acct_root_list(items, sep) := concat(sep, items) if count(items) <= 5

acct_root_list(items, sep) := sprintf("%s and %d more", [concat(sep, array.slice(items, 0, 5)), count(items) - 5]) if count(items) > 5

deny contains msg if {
	count(acct_root_claims) > 0
	count(acct_root_conflicts) > 0
	msg := sprintf("psd:root = account-baseline: set on %s, but %s. The tag marks the account-baseline root (templates/account-baseline/), where every provider configuration sets it in default_tags and nothing is tagged student-pii. Set it on every provider configuration there, or remove it from this root (%s)", [acct_root_list(acct_root_claims, ", "), acct_root_list(acct_root_conflicts, "; "), posture_rule])
}

acct_cfg := data.student_pii_account

acct_cfg_ok if {
	acct_cfg.present == true
	is_string(acct_cfg.breakglass_role_name)
	acct_cfg.breakglass_role_name != ""
	is_string(acct_cfg.breakglass_permission_set_name)
	acct_cfg.breakglass_permission_set_name != ""
	is_array(acct_cfg.managed_identifiers)
	is_array(acct_cfg.custom_identifier_names)
	count(acct_cfg.custom_identifier_names) > 0
}

acct_required_ids := array.concat(acct_cfg.managed_identifiers, acct_cfg.custom_identifier_names) if acct_cfg_ok

# An account data protection policy, read from after or, for a delete, before.
acct_dpp_change(rc) if {
	rc.type == "aws_cloudwatch_log_account_policy"
	some state in [rc.change.after, rc.change.before]
	state.policy_type == "DATA_PROTECTION_POLICY"
}

acct_dpp_writes := [rc |
	some rc in input.resource_changes
	acct_dpp_change(rc)
	some action in rc.change.actions
	action in {"create", "update"}
]

acct_policy_doc(rc) := json.unmarshal(rc.change.after.policy_document) if {
	is_string(rc.change.after.policy_document)
	json.is_valid(rc.change.after.policy_document)
}

acct_statements(doc) := doc.Statement if is_array(doc.Statement)

acct_statements(doc) := [doc.Statement] if is_object(doc.Statement)

# Identifiers that the statements carrying operation op (Audit or Deidentify) list.
acct_listed(doc, op) := {id |
	some st in acct_statements(doc)
	is_object(st.Operation)
	op in object.keys(st.Operation)
	some id in st.DataIdentifier
}

deny contains msg if {
	acct_app_root
	some rc in input.resource_changes
	acct_dpp_change(rc)
	some action in rc.change.actions
	action in {"create", "update", "delete"}
	msg := sprintf("%s: student-pii app root plans %s on the account data protection policy, which belongs to the account-baseline root (templates/account-baseline/); remove it from this root (%s)", [rc.address, concat(", ", rc.change.actions), posture_rule])
}

deny contains msg if {
	acct_baseline_root
	not acct_cfg_ok
	msg := sprintf("account-baseline root: data.student_pii_account is missing or incomplete, so the account data protection policy and the break-glass grant cannot be checked; the plan job derives it from cloud.aws.student_pii in the environment file (%s)", [posture_rule])
}

deny contains msg if {
	acct_baseline_root
	some rc in acct_dpp_writes
	not acct_policy_doc(rc)
	msg := sprintf("%s: policy_document is not known JSON at plan time, so its identifiers cannot be checked; build it with jsonencode from values known at plan time (%s)", [rc.address, posture_rule])
}

deny contains msg if {
	acct_baseline_root
	some rc in acct_dpp_writes
	doc := acct_policy_doc(rc)
	some op in ["Audit", "Deidentify"]
	listed := acct_listed(doc, op)
	missing := [id | some id in acct_required_ids; not id in listed]
	count(missing) > 0
	msg := sprintf("%s: the %s statement does not list %s; list every cloud.aws.student_pii managed_identifiers ARN and custom_identifiers name in both the Audit and the Deidentify statement (%s)", [rc.address, op, concat(", ", missing), posture_rule])
}
