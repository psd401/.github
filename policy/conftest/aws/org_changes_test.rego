# ABOUTME: Tests for org_changes.rego: AWS Organizations resources and organization trails are denied
# ABOUTME: on create, update or replace unless an active exceptions.yml entry for the rule waives them.
package aws

# Tests for org_changes.rego (13-aws-accounts.md rule 15). Inputs are inline,
# like student_pii_logs_test.rego; the shared fixtures' exceptions.json has no
# entry for this rule, and each exception test replaces data.exceptions.

org_rc(address, type, mode, actions, after) := {
	"address": address,
	"type": type,
	"mode": mode,
	"change": {"actions": actions, "after": after},
}

org_plan(rcs) := {"configuration": {"provider_config": {}}, "resource_changes": rcs}

org_entry(scope) := {
	"id": "psd-aws-infra-org-changes",
	"standard": "13-aws-accounts.md#org-level-changes",
	"rule": "org-level changes are made only in psd-aws-infra",
	"reason": "psd-aws-infra is the repo that manages the AWS Organization",
	"scope": scope,
	"approved_by": "CIO",
	"status": "active",
	"expires": "none",
}

scp := org_rc("aws_organizations_policy.deny_regions", "aws_organizations_policy", "managed", ["create"], {"type": "SERVICE_CONTROL_POLICY"})

test_org_policy_create_denied if {
	some msg in deny with input as org_plan([scp])
	contains(msg, "aws_organizations_policy.deny_regions")
	contains(msg, "psd401/psd-aws-infra")
	contains(msg, "13-aws-accounts.md rule 15")
}

test_org_account_update_denied if {
	acct := org_rc("aws_organizations_account.sandbox", "aws_organizations_account", "managed", ["update"], {"name": "sandbox"})
	some msg in deny with input as org_plan([acct])
	contains(msg, "aws_organizations_account.sandbox")
}

test_org_resource_replace_denied if {
	ou := org_rc("aws_organizations_organizational_unit.workloads", "aws_organizations_organizational_unit", "managed", ["delete", "create"], {"name": "Workloads"})
	some msg in deny with input as org_plan([ou])
	contains(msg, "aws_organizations_organizational_unit.workloads")
}

test_org_resource_noop_passes if {
	ou := org_rc("aws_organizations_organizational_unit.workloads", "aws_organizations_organizational_unit", "managed", ["no-op"], {"name": "Workloads"})
	count(deny) == 0 with input as org_plan([ou])
}

test_org_data_source_passes if {
	org := org_rc("data.aws_organizations_organization.this", "aws_organizations_organization", "data", ["read"], {})
	count(deny) == 0 with input as org_plan([org])
}

test_organization_trail_denied if {
	trail := org_rc("aws_cloudtrail.org", "aws_cloudtrail", "managed", ["create"], {"is_organization_trail": true, "name": "org"})
	some msg in deny with input as org_plan([trail])
	contains(msg, "aws_cloudtrail.org")
	contains(msg, "AWS Organizations change")
}

test_account_trail_passes if {
	trail := org_rc("aws_cloudtrail.app", "aws_cloudtrail", "managed", ["create"], {"is_organization_trail": false, "name": "app"})
	count(deny) == 0 with input as org_plan([trail])
}

test_org_change_with_plan_scoped_exception_passes if {
	trail := org_rc("aws_cloudtrail.org", "aws_cloudtrail", "managed", ["update"], {"is_organization_trail": true})
	count(deny) == 0 with input as org_plan([scp, trail])
		with data.exceptions as [org_entry("plan")]
}

test_org_change_with_address_prefix_exception_waives_only_that_prefix if {
	in_module := org_rc("module.org.aws_organizations_policy.scp", "aws_organizations_policy", "managed", ["create"], {})
	denies := deny with input as org_plan([scp, in_module])
		with data.exceptions as [org_entry("module.org")]
	count(denies) == 1
	some msg in denies
	startswith(msg, "aws_organizations_policy.deny_regions ")
}

test_org_change_with_expired_exception_denied if {
	expired := object.union(org_entry("plan"), {"expires": "2020-01-01"})
	some msg in deny with input as org_plan([scp])
		with data.exceptions as [expired]
	contains(msg, "aws_organizations_policy.deny_regions")
}

test_org_change_with_other_standard_exception_denied if {
	other := object.union(org_entry("plan"), {"id": "other", "standard": "08-iac.md#org-level-changes"})
	some msg in deny with input as org_plan([scp])
		with data.exceptions as [other]
	contains(msg, "aws_organizations_policy.deny_regions")
}
