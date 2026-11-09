# ABOUTME: Student-PII roots: 30-day KMS-encrypted log groups, no Bedrock text logging, no API data tracing.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "Student PII in logs" / 12-cloud-cost.md rule 5 (2026-10-23):
# in a root whose default_tags set psd:data-classification = student-pii,
# every log group caps at 30 days (unless tagged psd:log-content=none) and
# sets a customer-managed KMS key, Bedrock invocation logging runs with text
# delivery off, and no API Gateway stage turns on data tracing. The root is
# detected from tags_all, which the provider fills from default_tags. An
# exceptions.yml entry waives a finding only when its scope equals the
# resource address (exception_active_exact), never as a prefix.

pii_rule := "08-iac.md#student-pii-in-logs"

student_pii_root if {
	some rc in input.resource_changes
	rc.change.after.tags_all["psd:data-classification"] == "student-pii"
}

# No-op counts: reclassifying a root updates its taggable resources, but an
# untaggable one such as aws_api_gateway_method_settings stays no-op.
pii_changes(type) := [rc |
	student_pii_root
	some rc in input.resource_changes
	rc.type == type
	some action in rc.change.actions
	action in {"create", "update", "no-op"}
]

log_content_none(rc) if rc.change.after.tags_all["psd:log-content"] == "none"

log_content_none(rc) if rc.change.after.tags["psd:log-content"] == "none"

kms_set(rc) if {
	key := rc.change.after.kms_key_id
	is_string(key)
	key != ""
}

kms_set(rc) if rc.change.after_unknown.kms_key_id == true

deny contains msg if {
	some rc in pii_changes("aws_cloudwatch_log_group")
	not log_content_none(rc)
	rc.change.after.retention_in_days > 30
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, retention_in_days %v exceeds 30; cap it at 30 or tag the group psd:log-content=none (%s)", [rc.address, rc.change.after.retention_in_days, pii_rule])
}

deny contains msg if {
	some rc in pii_changes("aws_cloudwatch_log_group")
	not kms_set(rc)
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, log group has no kms_key_id; set a customer-managed KMS key (%s)", [rc.address, pii_rule])
}

text_delivery_off(rc) if {
	some lc in rc.change.after.logging_config
	lc.text_data_delivery_enabled == false
}

deny contains msg if {
	some rc in pii_changes("aws_bedrock_model_invocation_logging_configuration")
	not text_delivery_off(rc)
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, set logging_config.text_data_delivery_enabled = false; the provider default is true (%s)", [rc.address, pii_rule])
}

# In a student-pii root or the account-baseline root (acct_baseline_root,
# account_controls.rego), no content-delivery flag of a Bedrock invocation
# logging configuration is true. These are the four flags hashicorp/aws v6.70.0
# has. It has no argument for the API's audioDataDeliveryEnabled, so no plan
# check sees audio (templates/account-baseline/README.md, "Audio flag"). In a
# student-pii root the text rule above
# already reports text delivery.
bedrock_delivery_flags := {
	"text_data_delivery_enabled",
	"image_data_delivery_enabled",
	"embedding_data_delivery_enabled",
	"video_data_delivery_enabled",
}

bedrock_flags_checked := bedrock_delivery_flags - {"text_data_delivery_enabled"} if {
	student_pii_root
} else := bedrock_delivery_flags

bedrock_flag_root if student_pii_root

bedrock_flag_root if acct_baseline_root

# Each checked flag must be false. A null flag, or one unknown at plan time
# (left out of after), does not pass.
bedrock_flag_off(rc, f) if {
	some lc in rc.change.after.logging_config
	lc[f] == false
}

bedrock_flag_state(rc, f) := sprintf("%s %v", [f, v]) if {
	v := rc.change.after.logging_config[0][f]
} else := sprintf("%s not known at plan time", [f])

deny contains msg if {
	bedrock_flag_root
	some rc in input.resource_changes
	rc.type == "aws_bedrock_model_invocation_logging_configuration"
	some action in rc.change.actions
	action in {"create", "update", "no-op"}
	on := sort([bedrock_flag_state(rc, f) |
		some f in bedrock_flags_checked
		not bedrock_flag_off(rc, f)
	])
	count(on) > 0
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: Bedrock invocation logging does not turn content delivery off (%s); set every content-delivery flag in logging_config to false, the provider default is true (%s)", [rc.address, concat(", ", on), pii_rule])
}

deny contains msg if {
	some rc in pii_changes("aws_api_gateway_method_settings")
	some s in rc.change.after.settings
	s.data_trace_enabled == true
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, data_trace_enabled logs full request and response bodies; turn it off on every stage (%s)", [rc.address, pii_rule])
}

# HTTP and WebSocket APIs (API Gateway v2) set data tracing per stage, in the
# default route settings and per route.
deny contains msg if {
	some rc in pii_changes("aws_apigatewayv2_stage")
	some block in ["default_route_settings", "route_settings"]
	some s in rc.change.after[block]
	s.data_trace_enabled == true
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, %s data_trace_enabled logs full request and response bodies. Turn it off on every stage and route (%s)", [rc.address, block, pii_rule])
}
