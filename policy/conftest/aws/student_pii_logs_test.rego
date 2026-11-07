# ABOUTME: conftest verify tests for student_pii_logs.rego.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# Tests for student_pii_logs.rego (08-iac.md "Student PII in logs",
# 12-cloud-cost.md rule 5). A root is student-pii when any planned resource's
# tags_all carries psd:data-classification = student-pii (default_tags).

pii_tags := {"psd:data-classification": "student-pii"}

internal_tags := {"psd:data-classification": "internal"}

pii_marker := {
	"address": "aws_s3_bucket.data",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"tags_all": pii_tags}},
}

log_group(after, after_unknown) := {
	"address": "aws_cloudwatch_log_group.app",
	"type": "aws_cloudwatch_log_group",
	"change": {"actions": ["create"], "after": after, "after_unknown": after_unknown},
}

plan(rcs) := {"configuration": {"provider_config": {}}, "resource_changes": rcs}

good_lg := log_group({"name": "/app", "retention_in_days": 30, "kms_key_id": "arn:aws:kms:us-west-2:111111111111:key/k", "tags_all": pii_tags}, {})

test_pii_log_group_with_kms_and_30_days_passes if {
	count(deny) == 0 with input as plan([pii_marker, good_lg])
}

test_pii_log_group_over_30_days_denied if {
	lg := log_group({"name": "/app", "retention_in_days": 90, "kms_key_id": "arn:k", "tags_all": pii_tags}, {})
	some msg in deny with input as plan([lg])
	contains(msg, "student-pii")
	contains(msg, "30")
}

test_pii_log_group_tagged_log_content_none_may_keep_90_days if {
	lg := log_group({"name": "/app", "retention_in_days": 90, "kms_key_id": "arn:k", "tags": {"psd:log-content": "none"}, "tags_all": object.union(pii_tags, {"psd:log-content": "none"})}, {})
	count(deny) == 0 with input as plan([lg])
}

test_pii_log_group_without_kms_denied if {
	lg := log_group({"name": "/app", "retention_in_days": 30, "kms_key_id": null, "tags_all": pii_tags}, {})
	some msg in deny with input as plan([lg])
	contains(msg, "kms_key_id")
}

test_pii_log_group_with_kms_known_after_apply_passes if {
	lg := log_group({"name": "/app", "retention_in_days": 30, "tags_all": pii_tags}, {"kms_key_id": true})
	count(deny) == 0 with input as plan([lg])
}

test_log_content_none_does_not_waive_kms if {
	lg := log_group({"name": "/app", "retention_in_days": 30, "tags_all": object.union(pii_tags, {"psd:log-content": "none"})}, {})
	some msg in deny with input as plan([lg])
	contains(msg, "kms_key_id")
}

test_internal_root_log_group_without_kms_passes if {
	lg := log_group({"name": "/app", "retention_in_days": 90, "tags_all": internal_tags}, {})
	count(deny) == 0 with input as plan([lg])
}

bedrock_logging(lc) := {
	"address": "aws_bedrock_model_invocation_logging_configuration.this",
	"type": "aws_bedrock_model_invocation_logging_configuration",
	"change": {"actions": ["create"], "after": {"logging_config": [lc]}},
}

test_pii_bedrock_text_delivery_on_denied if {
	some msg in deny with input as plan([pii_marker, bedrock_logging({"text_data_delivery_enabled": true})])
	contains(msg, "text_data_delivery_enabled")
}

test_pii_bedrock_text_delivery_off_passes if {
	count(deny) == 0 with input as plan([pii_marker, bedrock_logging({"text_data_delivery_enabled": false})])
}

test_internal_bedrock_text_delivery_on_passes if {
	count(deny) == 0 with input as plan([bedrock_logging({"text_data_delivery_enabled": true})])
}

method_settings(stage, trace) := {
	"address": sprintf("aws_api_gateway_method_settings.%s", [stage]),
	"type": "aws_api_gateway_method_settings",
	"change": {"actions": ["create"], "after": {"stage_name": stage, "settings": [{"data_trace_enabled": trace}]}},
}

test_pii_data_trace_on_any_stage_denied if {
	some msg in deny with input as plan([pii_marker, method_settings("dev", true)])
	contains(msg, "data_trace_enabled")
}

test_pii_data_trace_off_passes if {
	count(deny) == 0 with input as plan([pii_marker, method_settings("dev", false)])
}

test_pii_exception_suppresses_the_finding if {
	lg := log_group({"name": "/app", "retention_in_days": 90, "kms_key_id": "arn:k", "tags_all": pii_tags}, {})
	count(deny) == 0 with input as plan([lg])
		with data.exceptions as [{
			"id": "pii-retention", "standard": "08-iac.md#student-pii-in-logs",
			"scope": "aws_cloudwatch_log_group.app", "status": "active", "expires": "none",
		}]
}

pii_entry(id, scope) := {
	"id": id, "standard": "08-iac.md#student-pii-in-logs",
	"scope": scope, "status": "active", "expires": "none",
}

# Each student-pii rule matches scope exactly: an entry for one address does
# not waive a longer address it is a prefix of.
test_pii_prefix_scoped_exception_does_not_waive_a_longer_address if {
	lg := object.union(
		log_group({"name": "/app-audit", "retention_in_days": 90, "kms_key_id": null, "tags_all": pii_tags}, {}),
		{"address": "aws_cloudwatch_log_group.app_audit"},
	)
	bedrock := object.union(
		bedrock_logging({"text_data_delivery_enabled": true}),
		{"address": "aws_bedrock_model_invocation_logging_configuration.this_v2"},
	)
	denies := deny with input as plan([pii_marker, lg, bedrock, method_settings("dev_v2", true)])
		with data.exceptions as [
			pii_entry("pii-app", "aws_cloudwatch_log_group.app"),
			pii_entry("pii-bedrock", "aws_bedrock_model_invocation_logging_configuration.this"),
			pii_entry("pii-dev-stage", "aws_api_gateway_method_settings.dev"),
		]
	some retention in denies
	startswith(retention, "aws_cloudwatch_log_group.app_audit: student-pii root, retention_in_days")
	some kms in denies
	startswith(kms, "aws_cloudwatch_log_group.app_audit: student-pii root, log group has no kms_key_id")
	some text in denies
	startswith(text, "aws_bedrock_model_invocation_logging_configuration.this_v2: student-pii root, set logging_config")
	some trace in denies
	startswith(trace, "aws_api_gateway_method_settings.dev_v2: student-pii root, data_trace_enabled")
}
