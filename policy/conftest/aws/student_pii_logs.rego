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

pii_changes(type) := [rc |
	student_pii_root
	some rc in input.resource_changes
	rc.type == type
	some action in rc.change.actions
	action in {"create", "update"}
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

deny contains msg if {
	some rc in pii_changes("aws_api_gateway_method_settings")
	some s in rc.change.after.settings
	s.data_trace_enabled == true
	not exception_active_exact(pii_rule, rc.address)
	msg := sprintf("%s: student-pii root, data_trace_enabled logs full request and response bodies; turn it off on every stage (%s)", [rc.address, pii_rule])
}
