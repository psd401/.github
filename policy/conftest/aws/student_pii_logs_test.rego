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

# Every deny except student_pii_destinations.rego's, which denies any Bedrock
# logging configuration in a student-pii or account-baseline root. The Bedrock pass tests below
# check the log rules alone.
log_denies := {msg |
	some msg in deny
	not endswith(msg, sprintf("(%s)", [dest_rule]))
}

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

# The text rule alone: the flag rule below denies the other three flags when
# they are left out, as a value unknown at plan time is.
test_pii_bedrock_text_delivery_off_passes if {
	msgs := log_denies with input as plan([pii_marker, bedrock_logging({"text_data_delivery_enabled": false})])
	not contains(concat("\n", msgs), "set logging_config.text_data_delivery_enabled = false")
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

# Content-delivery flags beyond text. hashicorp/aws v6.70.0 plans each unset
# flag as true, so a real plan shows all four. It has no audio argument.
bedrock_flag_all_off := {
	"text_data_delivery_enabled": false, "image_data_delivery_enabled": false,
	"embedding_data_delivery_enabled": false, "video_data_delivery_enabled": false,
}

bedrock_flag_findings(msgs) := {m |
	some m in msgs
	startswith(m, "aws_bedrock_model_invocation_logging_configuration.this:")
	endswith(m, "(08-iac.md#student-pii-in-logs)")
}

test_pii_bedrock_image_embedding_or_video_delivery_on_denied if {
	every flag in ["image_data_delivery_enabled", "embedding_data_delivery_enabled", "video_data_delivery_enabled"] {
		lc := object.union(bedrock_flag_all_off, {flag: true})
		findings := bedrock_flag_findings(deny) with input as plan([pii_marker, bedrock_logging(lc)])
		count(findings) == 1
		some m in findings
		contains(m, sprintf("%s true", [flag]))
	}
}

# In a student-pii root the text rule above reports text delivery, so the flag
# rule does not report it a second time.
test_pii_bedrock_text_delivery_on_reported_once if {
	lc := object.union(bedrock_flag_all_off, {"text_data_delivery_enabled": true})
	findings := bedrock_flag_findings(deny) with input as plan([pii_marker, bedrock_logging(lc)])
	count(findings) == 1
}

test_pii_bedrock_with_every_flag_off_passes if {
	count(log_denies) == 0 with input as plan([pii_marker, bedrock_logging(bedrock_flag_all_off)])
}

# The account-baseline root keeps no Bedrock logging configuration at all.
# student_pii_destinations.rego denies one there outright, so the flag rule
# does not report it a second time.
test_baseline_bedrock_flags_on_left_to_the_destinations_rule if {
	lc := object.union(bedrock_flag_all_off, {"image_data_delivery_enabled": true})
	findings := bedrock_flag_findings(deny) with input as plan([acct_baseline_marker, bedrock_logging(lc)])
		with data.student_pii_account as data.acct_student_pii_account
	count(findings) == 0
}

test_bedrock_flag_finding_waived_by_an_exact_entry if {
	lc := object.union(bedrock_flag_all_off, {"video_data_delivery_enabled": true})
	findings := bedrock_flag_findings(deny) with input as plan([pii_marker, bedrock_logging(lc)])
		with data.exceptions as [pii_entry("pii-bedrock", "aws_bedrock_model_invocation_logging_configuration.this")]
	count(findings) == 0
}

no_op(rc) := json.patch(rc, [{"op": "replace", "path": "/change/actions", "value": ["no-op"]}])

# The text rule reports text delivery; the flag rule reports the other three.
test_pii_bedrock_no_op_with_flags_on_denied if {
	lc := {"text_data_delivery_enabled": true, "image_data_delivery_enabled": true, "embedding_data_delivery_enabled": true, "video_data_delivery_enabled": true}
	findings := bedrock_flag_findings(deny) with input as plan([pii_marker, no_op(bedrock_logging(lc))])
	count(findings) == 2
	some m in findings
	contains(m, "(embedding_data_delivery_enabled true, image_data_delivery_enabled true, video_data_delivery_enabled true)")
}

# A flag must be false. terraform show -json omits a value unknown at plan time.
test_pii_bedrock_flag_null_or_unknown_denied if {
	null_image := object.union(bedrock_flag_all_off, {"image_data_delivery_enabled": null})
	unknown_video := object.remove(bedrock_flag_all_off, {"video_data_delivery_enabled"})
	every lc_and_needle in [[null_image, "(image_data_delivery_enabled null)"], [unknown_video, "(video_data_delivery_enabled not known at plan time)"]] {
		findings := bedrock_flag_findings(deny) with input as plan([pii_marker, bedrock_logging(lc_and_needle[0])])
		count(findings) == 1
		some m in findings
		contains(m, lc_and_needle[1])
	}
}

# Reclassifying a root updates its taggable resources. An untaggable one such
# as aws_api_gateway_method_settings stays no-op and still counts.
test_pii_reclassified_root_no_op_data_trace_denied if {
	marker := json.patch(pii_marker, [{"op": "replace", "path": "/change/actions", "value": ["update"]}])
	some msg in deny with input as plan([marker, no_op(method_settings("prod", true))])
	startswith(msg, "aws_api_gateway_method_settings.prod: student-pii root, data_trace_enabled")
}

apigwv2_stage(settings) := {
	"address": "aws_apigatewayv2_stage.ws",
	"type": "aws_apigatewayv2_stage",
	"change": {"actions": ["create"], "after": object.union({"name": "prod", "default_route_settings": [], "route_settings": []}, settings)},
}

test_pii_websocket_stage_data_trace_denied if {
	every block in ["default_route_settings", "route_settings"] {
		stage := apigwv2_stage({block: [{"data_trace_enabled": true, "logging_level": "INFO"}]})
		some msg in deny with input as plan([pii_marker, stage])
		startswith(msg, sprintf("aws_apigatewayv2_stage.ws: student-pii root, %s data_trace_enabled logs full request and response bodies", [block]))
	}
	off := apigwv2_stage({"default_route_settings": [{"data_trace_enabled": false}], "route_settings": [{"route_key": "$connect", "data_trace_enabled": false}]})
	count(log_denies) == 0 with input as plan([pii_marker, off])
}

pii_long_retention := log_group({"name": "/app", "retention_in_days": 90, "kms_key_id": "arn:k", "tags_all": pii_tags}, {})

test_pii_expired_exact_entry_does_not_waive if {
	some msg in deny with input as plan([pii_long_retention])
		with data.exceptions as [object.union(pii_entry("pii-retention", "aws_cloudwatch_log_group.app"), {"expires": "2020-01-01"})]
	startswith(msg, "aws_cloudwatch_log_group.app: student-pii root, retention_in_days 90 exceeds 30")
}

test_pii_inactive_exact_entry_does_not_waive if {
	some msg in deny with input as plan([pii_long_retention])
		with data.exceptions as [object.union(pii_entry("pii-retention", "aws_cloudwatch_log_group.app"), {"status": "superseded"})]
	startswith(msg, "aws_cloudwatch_log_group.app: student-pii root, retention_in_days 90 exceeds 30")
}
