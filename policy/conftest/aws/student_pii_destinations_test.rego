# ABOUTME: Tests for student_pii_destinations.rego: each log destination kind in a student-pii root
# ABOUTME: denies without an exact-scope exception, Bedrock S3 and app-root Bedrock logging deny outright.
package aws

# Fixtures (policy/conftest/fixtures/aws/dest_*.json): dest_plan_pii holds one
# resource per destination kind plus look-alikes that must pass, in a root
# tagged student-pii. dest_plan_internal is the same resource list in an
# internal root. dest_plan_baseline is an account-baseline root that also
# carries the student-pii tag. dest_telemetry_layers stands in for
# policy/data/telemetry-layers.yml, which conftest verify does not load.

dt_rule := "08-iac.md#student-pii-log-destinations"

# Only this file's rule id: the per-root log rules also
# deny these plans, and their own tests cover them.
dt_denies := {msg |
	some msg in deny
	endswith(msg, sprintf("(%s)", [dt_rule]))
}

dt_pii_denies := d if {
	d := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
}

dt_flagged(denies, address) if {
	some msg in denies
	startswith(msg, sprintf("%s: ", [address]))
}

dt_starts(denies, prefix) if {
	some msg in denies
	startswith(msg, prefix)
}

dt_denied(denies, address, kind) if {
	some msg in denies
	startswith(msg, sprintf("%s: student-pii root, ", [address]))
	contains(msg, sprintf("(destination kind %s)", [kind]))
}

# The schema requires a destination block on every entry under dt_rule.
dt_entry(standard, scope, kind) := {
	"id": "dest-entry", "standard": standard, "scope": scope,
	"status": "active", "expires": "none", "destination": {"kind": kind},
}

test_dest_subscription_filter_denied if {
	dt_denied(dt_pii_denies, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")
}

test_dest_log_destination_denied if {
	dt_denied(dt_pii_denies, "aws_cloudwatch_log_destination.central", "log-destination")
}

test_dest_account_subscription_policy_denied_and_masking_policy_passes if {
	dt_denied(dt_pii_denies, "aws_cloudwatch_log_account_policy.subscribe_all", "account-subscription")
	not dt_flagged(dt_pii_denies, "aws_cloudwatch_log_account_policy.masking")
}

test_dest_existing_firehose_no_op_denied if {
	dt_denied(dt_pii_denies, "aws_kinesis_firehose_delivery_stream.ship", "firehose")
}

test_dest_log_delivery_denied if {
	dt_denied(dt_pii_denies, "aws_cloudwatch_log_delivery.kb", "log-delivery")
}

test_dest_s3_export_target_denied_and_other_bucket_policy_passes if {
	dt_denied(dt_pii_denies, "aws_s3_bucket_policy.export_target", "s3-export")
	not dt_flagged(dt_pii_denies, "aws_s3_bucket_policy.cdn_read")
}

test_dest_ecs_log_driver_to_a_non_cloudwatch_target_denied if {
	some splunk in dt_pii_denies
	startswith(splunk, "aws_ecs_task_definition.app: student-pii root, container shipper log driver splunk (destination kind ecs-log-driver)")
	some firelens in dt_pii_denies
	startswith(firelens, "aws_ecs_task_definition.app: student-pii root, container router log driver awsfirelens with output firehose (destination kind ecs-log-driver)")
}

test_dest_ecs_awslogs_and_firelens_to_cloudwatch_pass if {
	dt_denied(dt_pii_denies, "aws_ecs_task_definition.app", "ecs-log-driver")
	not dt_starts(dt_pii_denies, "aws_ecs_task_definition.app: student-pii root, container app log driver")
	not dt_starts(dt_pii_denies, "aws_ecs_task_definition.app: student-pii root, container sidecar")
}

test_dest_lambda_telemetry_layer_denied_and_other_layer_passes if {
	some msg in dt_pii_denies
	startswith(msg, "aws_lambda_function.api: student-pii root, Lambda layer arn:aws:lambda:us-west-2:464622532012:layer:Datadog-Extension:99 (Datadog) (destination kind lambda-telemetry)")
	not contains(concat("\n", dt_pii_denies), "shared-utils")
}

test_dest_lambda_layers_without_the_telemetry_list_denied if {
	denies := dt_denies with input as data.dest_plan_pii
	some msg in denies
	startswith(msg, "aws_lambda_function.api: student-pii root, the function has Lambda layers but data.telemetry_layers is missing")
	not dt_flagged(denies, "aws_lambda_function.plain")
}

test_dest_otel_exporter_variable_on_lambda_and_ecs_denied if {
	some lambda in dt_pii_denies
	startswith(lambda, "aws_lambda_function.api: student-pii root, environment variable OTEL_EXPORTER_OTLP_LOGS_ENDPOINT (destination kind otel-exporter)")
	some ecs in dt_pii_denies
	startswith(ecs, "aws_ecs_task_definition.app: student-pii root, container app environment variable OTEL_EXPORTER_OTLP_ENDPOINT (destination kind otel-exporter)")
	not dt_flagged(dt_pii_denies, "aws_lambda_function.plain")
}

test_dest_deleted_destination_not_flagged if {
	dt_denied(dt_pii_denies, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")
	not dt_flagged(dt_pii_denies, "aws_cloudwatch_log_subscription_filter.retired")
}

test_dest_exact_scope_exception_waives_only_its_address if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [dt_entry(dt_rule, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")]
	not dt_flagged(denies, "aws_cloudwatch_log_subscription_filter.ship")
	dt_denied(denies, "aws_cloudwatch_log_destination.central", "log-destination")
}

test_dest_prefix_scope_or_other_standard_does_not_waive if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [
			dt_entry(dt_rule, "aws_cloudwatch_log_subscription_filter", "subscription-filter"),
			dt_entry(dt_rule, "aws_cloudwatch_log_subscription_filter.shi", "subscription-filter"),
			dt_entry("08-iac.md#student-pii-in-logs", "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter"),
		]
	dt_denied(denies, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")
}

test_dest_bedrock_s3_config_denied_even_with_an_exception if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [dt_entry(dt_rule, "aws_bedrock_model_invocation_logging_configuration.this", "bedrock-s3")]
	dt_denied(denies, "aws_bedrock_model_invocation_logging_configuration.this", "bedrock-s3")
}

test_dest_bedrock_config_in_a_student_pii_app_root_denied_even_with_an_exception if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [dt_entry(dt_rule, "aws_bedrock_model_invocation_logging_configuration.this", "bedrock-s3")]
	some msg in denies
	startswith(msg, "aws_bedrock_model_invocation_logging_configuration.this: student-pii app root, the Bedrock invocation logging configuration belongs to the account-baseline root")
}

test_dest_baseline_root_owns_bedrock_logging_but_not_its_s3_delivery if {
	denies := dt_denies with input as data.dest_plan_baseline
	not dt_starts(denies, "aws_bedrock_model_invocation_logging_configuration.this: student-pii app root")
	some msg in denies
	startswith(msg, "aws_bedrock_model_invocation_logging_configuration.this: account-baseline root, Bedrock invocation logging writes to S3 through cloudwatch_config.large_data_delivery_s3_config (destination kind bedrock-s3)")
}

test_dest_internal_root_unaffected if {
	count(dt_pii_denies) > 0
	count(dt_denies) == 0 with input as data.dest_plan_internal
		with data.telemetry_layers as data.dest_telemetry_layers
	count(dt_denies) == 0 with input as data.dest_plan_internal
}

# The account-baseline root is not tagged student-pii (account_controls.rego),
# yet it owns the account's one Bedrock invocation logging configuration.
test_dest_untagged_baseline_root_bedrock_s3_delivery_denied if {
	plan := json.patch(data.acct_plan_baseline, [{
		"op": "replace",
		"path": "/resource_changes/0/change/after/logging_config/0/s3_config",
		"value": [{"bucket_name": "district-bedrock-logs", "key_prefix": ""}],
	}])
	denies := dt_denies with input as plan
	some msg in denies
	startswith(msg, "aws_bedrock_model_invocation_logging_configuration.this: ")
	contains(msg, "through s3_config (destination kind bedrock-s3)")
	count(dt_denies) == 0 with input as data.acct_plan_baseline
}

# terraform show -json leaves a value unknown at plan time out of after and
# lists its key in after_unknown.
test_dest_otel_exporter_variable_unknown_at_plan_denied if {
	fn := {
		"address": "aws_lambda_function.api",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {"function_name": "api", "layers": [], "environment": [{"variables": {"LOG_LEVEL": "info"}}]},
			"after_unknown": {"environment": [{"variables": {"OTEL_EXPORTER_OTLP_ENDPOINT": true}}]},
		},
	}
	denies := dt_denies with input as plan([pii_marker, fn])
	count(denies) == 1
	some msg in denies
	startswith(msg, "aws_lambda_function.api: student-pii root, environment variable OTEL_EXPORTER_OTLP_ENDPOINT (destination kind otel-exporter)")
}

test_dest_ecs_container_definitions_unknown_at_plan_denied if {
	task := {
		"address": "aws_ecs_task_definition.app",
		"type": "aws_ecs_task_definition",
		"change": {"actions": ["create"], "after": {"family": "app"}, "after_unknown": {"container_definitions": true}},
	}
	denies := dt_denies with input as plan([pii_marker, task])
	count(denies) == 1
	some msg in denies
	startswith(msg, "aws_ecs_task_definition.app: student-pii root, container_definitions is not known at plan time")
	contains(msg, "(destination kind ecs-log-driver)")
	count(dt_denies) == 0 with input as plan([pii_marker, task])
		with data.exceptions as [dt_entry(dt_rule, "aws_ecs_task_definition.app", "ecs-log-driver")]
	count(dt_denies) == 1 with input as plan([pii_marker, task])
		with data.exceptions as [dt_entry(dt_rule, "aws_ecs_task_definition.app", "otel-exporter")]
}

# The account subscription filter policy ships every log group in the account,
# so it counts in the untagged account-baseline root too.
dt_baseline_subscription := json.patch(data.acct_plan_baseline, [{"op": "add", "path": "/resource_changes/-", "value": {
	"address": "aws_cloudwatch_log_account_policy.ship_all",
	"type": "aws_cloudwatch_log_account_policy",
	"change": {"actions": ["create"], "before": null, "after_unknown": {}, "after": {
		"policy_name": "ship-all", "policy_type": "SUBSCRIPTION_FILTER_POLICY", "scope": "ALL",
		"policy_document": `{"DestinationArn":"arn:aws:firehose:us-west-2:999999999999:deliverystream/vendor","FilterPattern":""}`,
	}},
}}])

test_dest_untagged_baseline_root_account_subscription_policy_denied if {
	denies := dt_denies with input as dt_baseline_subscription
	count(denies) == 1
	some msg in denies
	startswith(msg, "aws_cloudwatch_log_account_policy.ship_all: account-baseline root, account-level subscription filter policy (destination kind account-subscription)")
	count(dt_denies) == 0 with input as dt_baseline_subscription
		with data.exceptions as [dt_entry(dt_rule, "aws_cloudwatch_log_account_policy.ship_all", "account-subscription")]
}

# One address with two destination kinds needs one entry per kind.
test_dest_entry_waives_only_its_destination_kind if {
	telemetry := dt_entry(dt_rule, "aws_lambda_function.api", "lambda-telemetry")
	one := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [telemetry]
	not dt_denied(one, "aws_lambda_function.api", "lambda-telemetry")
	dt_denied(one, "aws_lambda_function.api", "otel-exporter")
	otel := object.union(dt_entry(dt_rule, "aws_lambda_function.api", "otel-exporter"), {"id": "dest-entry-2"})
	both := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [telemetry, otel]
	not dt_flagged(both, "aws_lambda_function.api")
}

dt_bucket_policy(principal) := {
	"address": "aws_s3_bucket_policy.export",
	"type": "aws_s3_bucket_policy",
	"change": {"actions": ["create"], "after": {"bucket": "d", "policy": json.marshal({
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::d/*"}],
	})}},
}

# An Allow to any principal lets logs.amazonaws.com write too.
test_dest_s3_bucket_policy_allowing_any_principal_denied if {
	every principal in ["*", {"AWS": "*"}, {"AWS": ["arn:aws:iam::111111111111:root", "*"]}] {
		denies := dt_denies with input as plan([pii_marker, dt_bucket_policy(principal)])
		count(denies) == 1
		some msg in denies
		startswith(msg, "aws_s3_bucket_policy.export: student-pii root, bucket policy letting any principal (*) write")
		contains(msg, "(destination kind s3-export)")
	}
	count(dt_denies) == 0 with input as plan([pii_marker, dt_bucket_policy({"AWS": "arn:aws:iam::111111111111:root"})])
}

dt_ship_entry := dt_entry(dt_rule, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")

test_dest_expired_exact_entry_does_not_waive if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [object.union(dt_ship_entry, {"expires": "2020-01-01"})]
	dt_denied(denies, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")
}

test_dest_inactive_exact_entry_does_not_waive if {
	denies := dt_denies with input as data.dest_plan_pii
		with data.telemetry_layers as data.dest_telemetry_layers
		with data.exceptions as [object.union(dt_ship_entry, {"status": "pending-review"})]
	dt_denied(denies, "aws_cloudwatch_log_subscription_filter.ship", "subscription-filter")
}
