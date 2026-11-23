# ABOUTME: conftest verify tests for the aws package, run against fixtures/aws.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# conftest verify --policy policy/conftest/aws --data policy/conftest/fixtures/aws
#
# Fixture files under fixtures/aws/ wrap their plan JSON under a top-level
# key matching the filename (e.g. plan_ok.json -> {"plan_ok": {...}}), since
# conftest merges every --data file's top-level keys straight into `data`
# and unwrapped fixtures sharing keys like "resource_changes" would collide.

test_plan_ok_has_no_denials if {
	count(deny) == 0 with input as data.plan_ok
}

test_tags_missing_denied if {
	count(deny) > 0 with input as data.plan_tags_missing
}

test_region_denied if {
	some msg in deny with input as data.plan_region_denied
	contains(msg, "not in the allowed set")
}

test_region_consistency_mismatch_denied if {
	# #24: the shared exceptions.json fixture declares "bedrockapp"'s
	# canonical region as us-east-1 (08-iac.md#region-consistency); this
	# dev plan uses us-west-2 for that same app, so it must be denied even
	# though us-west-2 is itself an allowed region.
	some msg in deny with input as data.plan_region_consistency_mismatch
	contains(msg, "region-consistency")
}

test_region_consistency_match_passes if {
	count(deny) == 0 with input as data.plan_region_consistency_ok
}

test_iam_user_denied if {
	some msg in deny with input as data.plan_iam_user
	contains(msg, "IAM roles only")
}

test_stateful_delete_without_exception_denied if {
	some msg in deny with input as data.plan_stateful_no_exception
	contains(msg, "stateful-resource-change")
}

test_stateful_delete_with_active_exception_passes if {
	count(deny) == 0 with input as {
		"configuration": {"provider_config": {}},
		"resource_changes": [{
			"address": "aws_s3_bucket.artifacts",
			"type": "aws_s3_bucket",
			"change": {"actions": ["delete", "create"], "after": {}},
		}],
	}
}

test_nat_multiple_denied if {
	# The shared exceptions.json fixture carries an active entry for
	# 12-cloud-cost.md#nat-is-the-exception scoped to "plan", so the
	# multiple-NAT-gateways denial is suppressed here; the missing-gateway-
	# endpoints denial is a separate rule that exception doesn't cover.
	some msg in deny with input as data.plan_nat_multiple
	contains(msg, "missing gateway VPC endpoints")
}

test_nat_multiple_without_exception_denied if {
	some msg in deny with input as data.plan_nat_multiple
		with data.exceptions as []
	contains(msg, "more than one")
}

test_nat_exception_citing_wrong_standard_file_still_denied if {
	# Regression for #19: rule_id_match used to accept a loose substring
	# match against the entry's "standard" field, so an entry citing the
	# wrong standard file but repeating the right anchor text could still
	# suppress a finding. This entry names 15-onprem-platform.md, not
	# 12-cloud-cost.md, so it must not suppress the denial.
	some msg in deny with input as data.plan_nat_multiple
		with data.exceptions as [{
			"id": "nat-wrong-file",
			"standard": "15-onprem-platform.md#nat-is-the-exception",
			"rule": "more than one NAT gateway per VPC needs an acknowledged suppression",
			"reason": "wrong-standard citation; must not suppress",
			"scope": "plan",
			"approved_by": "network admin",
			"status": "active",
			"expires": "none",
		}]
	contains(msg, "more than one")
}

# exception_active_exact: the entry's standard and scope must both equal the
# caller's. No prefix scope, no id match.
exact_entry(id, standard, scope) := {
	"id": id, "standard": standard, "scope": scope,
	"status": "active", "expires": "none",
}

test_exact_accepts_exact_entry if {
	exception_active_exact(pii_rule, "aws_cloudwatch_log_group.app")
		with data.exceptions as [exact_entry("pii-app", pii_rule, "aws_cloudwatch_log_group.app")]
}

test_exact_rejects_prefix_scope if {
	not exception_active_exact(pii_rule, "aws_cloudwatch_log_group.app_audit")
		with data.exceptions as [exact_entry("pii-app", pii_rule, "aws_cloudwatch_log_group.app")]
}

test_exact_rejects_empty_scope if {
	not exception_active_exact(pii_rule, "aws_cloudwatch_log_group.app")
		with data.exceptions as [exact_entry("pii-all", pii_rule, "")]
}

test_exact_rejects_id_only_match if {
	not exception_active_exact(pii_rule, "aws_cloudwatch_log_group.app")
		with data.exceptions as [exact_entry(pii_rule, "12-cloud-cost.md#log-retention", "aws_cloudwatch_log_group.app")]
}

test_s3_lifecycle_missing_denied if {
	some msg in deny with input as data.plan_s3_lifecycle_missing
	contains(msg, "noncurrent_version_expiration")
}

test_log_retention_missing_denied if {
	some msg in deny with input as data.plan_log_retention_missing
	contains(msg, "retention_in_days")
}

test_lambda_log_pairing_missing_denied if {
	some msg in deny with input as data.plan_lambda_log_missing
	contains(msg, "no matching aws_cloudwatch_log_group")
}

test_arm64_missing_denied if {
	some msg in deny with input as data.plan_arm64_missing
	contains(msg, "arm64-by-default")
}

test_serverless_nonzero_denied if {
	some msg in deny with input as data.plan_serverless_nonzero
	contains(msg, "must auto-pause")
}

test_alarm_literal_dimensions_denied if {
	some msg in deny with input as data.plan_alarm_literal
	contains(msg, "literal map")
}

test_rds_public_denied if {
	some msg in deny with input as data.plan_rds_public
	contains(msg, "publicly accessible")
}

test_tags_no_default_tags_block_denied if {
	some msg in deny with input as data.plan_tags_no_block
	contains(msg, "has no default_tags block")
}

# Terraform 1.16.5 plans `tags = { "psd:application" = var.app, ... }` (and
# `tags = var.tags`) as {"references": [...]}: the keys are checked against
# each planned resource's tags_all instead.
test_tags_references_with_no_taggable_resources_pass if {
	count(deny) == 0 with input as data.plan_tags_expression
}

test_tags_references_complete_tags_all_pass if {
	count(deny) == 0 with input as data.plan_tags_references_complete
}

test_tags_references_missing_key_denied if {
	findings := {msg | some msg in deny with input as data.plan_tags_references_missing}
	count(findings) == 1
	some msg in findings
	contains(msg, "aws_sns_topic.app")
	contains(msg, "psd:owner")
	contains(msg, "psd:repo")
	not contains(msg, "psd:application")
}

test_tags_references_missing_key_on_noop_denied if {
	some msg in deny with input as data.plan_tags_references_missing_noop
	contains(msg, "aws_sns_topic.steady")
	contains(msg, "psd:repo")
}

test_tags_references_unknown_tags_all_denied if {
	some msg in deny with input as data.plan_tags_references_unknown
	contains(msg, "aws_sns_topic.computed")
	contains(msg, "unknown at plan")
}

# The template's own default_tags shape: literal keys, variable values.
test_tags_variable_values_pass if {
	count(deny) == 0 with input as data.plan_tags_variable_values
}
