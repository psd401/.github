# ABOUTME: 13-aws-accounts.md rule 15: an app repo plan never creates or updates an AWS Organizations resource
# ABOUTME: or an organization trail; the repo that manages the Organization is exempted through exceptions.yml.
package aws

# 13-aws-accounts.md rule 15 (Kris, approved as a conftest rule 2026-11-09):
# org-level changes are requested as an issue in psd401/psd-aws-infra and
# made there, never in an app repo. A plan that creates or updates (a replace
# includes "create") any managed aws_organizations_* resource, or an
# aws_cloudtrail with is_organization_trail = true, is denied.
#
# Rego sees only the plan, never the repo name, so psd-aws-infra (the one
# repo allowed to make these changes) is exempted by an active exceptions.yml
# entry whose standard is org_changes_rule. Scope "plan" waives every finding
# of this rule in the plan; a resource address (or an address prefix, such as
# "module.org") waives only the addresses it covers (exception_active).
#
# The calling repo supplies exceptions.yml, so nothing in Rego or
# check_exceptions.py stops an app repo from adding the same entry: the
# limit to psd-aws-infra holds only as far as review of each repo's
# exceptions.yml (CODEOWNERS routes it to reviewers) catches it.

org_changes_rule := "13-aws-accounts.md#org-level-changes"

org_change_actions := {"create", "update"}

org_change(rc) if {
	rc.mode == "managed"
	startswith(rc.type, "aws_organizations_")
}

org_change(rc) if {
	rc.mode == "managed"
	rc.type == "aws_cloudtrail"
	rc.change.after.is_organization_trail == true
}

org_changes_waived_for_plan if exception_active(org_changes_rule, "plan")

deny contains msg if {
	some rc in input.resource_changes
	org_change(rc)
	some action in rc.change.actions
	action in org_change_actions
	not org_changes_waived_for_plan
	not exception_active(org_changes_rule, rc.address)
	msg := sprintf("%s (%s) is an AWS Organizations change; org-level changes are requested as an issue in psd401/psd-aws-infra and made there, never in an app repo (13-aws-accounts.md rule 15, %s)", [rc.address, rc.type, org_changes_rule])
}
