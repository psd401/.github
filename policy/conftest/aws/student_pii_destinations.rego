# ABOUTME: Log destination gate for 08-iac.md "Student PII log destinations": a resource in a student-pii
# ABOUTME: root that sends log content outside its CloudWatch log groups needs an exact-scope exception.
package aws

# student_pii_root comes from student_pii_logs.rego and
# exception_active_exact_kind from exceptions.rego. Every destination is a
# disclosure to whoever operates its target, so each one is a finding until an
# exceptions.yml entry for dest_rule names its exact address and its kind as
# destination.kind. check_exceptions.py then requires the entry's destination
# block. Kind tokens are the destination.kind enum in
# schemas/iac/exceptions.schema.json.
#
# data.telemetry_layers is policy/data/telemetry-layers.yml, passed to conftest
# with --data. Its rows match vendor Lambda layer ARNs. A function with layers
# in a student-pii root fails closed when the list did not reach conftest.

dest_rule := "08-iac.md#student-pii-log-destinations"

# Create, update and no-op all count: a destination that already exists keeps
# sending, so an expired entry fails the next plan. A replace carries
# "create". Deletes and data-source reads do not count.
dest_live_actions := {"create", "update", "no-op"}

dest_changes(type) := {rc |
	student_pii_root
	some rc in input.resource_changes
	rc.type == type
	some action in rc.change.actions
	action in dest_live_actions
}

# The root's label in messages. Account-level resources (the account
# subscription filter policy and Bedrock invocation logging) also count in the
# account-baseline root (acct_baseline_root, account_controls.rego), which owns
# them and is not tagged student-pii.
dest_root := "account-baseline root" if acct_baseline_root

else := "student-pii root" if student_pii_root

dest_account_changes(type) := {rc |
	dest_root
	some rc in input.resource_changes
	rc.type == type
	some action in rc.change.actions
	action in dest_live_actions
}

dest_findings contains {"address": rc.address, "kind": "subscription-filter", "what": "subscription filter"} if {
	some rc in dest_changes("aws_cloudwatch_log_subscription_filter")
}

dest_findings contains {"address": rc.address, "kind": "log-destination", "what": "CloudWatch Logs destination"} if {
	some rc in dest_changes("aws_cloudwatch_log_destination")
}

dest_findings contains {"address": rc.address, "kind": "account-subscription", "what": "account-level subscription filter policy"} if {
	some rc in dest_account_changes("aws_cloudwatch_log_account_policy")
	rc.change.after.policy_type == "SUBSCRIPTION_FILTER_POLICY"
}

dest_findings contains {"address": rc.address, "kind": "firehose", "what": "Firehose delivery stream"} if {
	some rc in dest_changes("aws_kinesis_firehose_delivery_stream")
}

dest_findings contains {"address": rc.address, "kind": "log-delivery", "what": "CloudWatch Logs delivery"} if {
	some rc in dest_changes("aws_cloudwatch_log_delivery")
}

# S3 export: Terraform has no export-task resource, and the boundary's
# DenyLogExport blocks the call. The plan still shows the target, since an
# export bucket must grant logs.<region>.amazonaws.com (AWS docs,
# S3ExportTasksConsole). The vended-log principal delivery.logs.amazonaws.com
# does not match this pattern.
dest_as_list(x) := x if is_array(x)

dest_as_list(x) := [x] if is_object(x)

dest_as_list(x) := [x] if is_string(x)

dest_statements(policy) := dest_as_list(json.unmarshal(policy).Statement) if is_string(policy)

dest_findings contains {"address": rc.address, "kind": "s3-export", "what": sprintf("bucket policy letting %s write, a CloudWatch Logs export target", [svc])} if {
	some rc in dest_changes("aws_s3_bucket_policy")
	some st in dest_statements(rc.change.after.policy)
	st.Effect == "Allow"
	some svc in dest_as_list(st.Principal.Service)
	regex.match(`^logs\.([a-z0-9-]+\.)?amazonaws\.com$`, svc)
}

# An Allow to any principal covers the logs service principal too.
dest_any_principal(principal) if principal == "*"

dest_any_principal(principal) if "*" in dest_as_list(principal.AWS)

dest_findings contains {"address": rc.address, "kind": "s3-export", "what": "bucket policy letting any principal (*) write, which includes a CloudWatch Logs export"} if {
	some rc in dest_changes("aws_s3_bucket_policy")
	some st in dest_statements(rc.change.after.policy)
	st.Effect == "Allow"
	dest_any_principal(st.Principal)
}

# ECS: container_definitions is a JSON string in the plan. awslogs writes to
# the account's CloudWatch Logs. FireLens reaches CloudWatch Logs through the
# Fluent Bit output cloudwatch_logs or the older Go plugin cloudwatch
# (aws-samples/amazon-ecs-firelens-examples). Every other driver or output,
# and FireLens with no Name option (a custom config file), is a destination.
dest_containers(rc) := json.unmarshal(rc.change.after.container_definitions) if {
	is_string(rc.change.after.container_definitions)
}

dest_firelens_cloudwatch := {"cloudwatch", "cloudwatch_logs"}

dest_cloudwatch_driver(lc) if lc.logDriver == "awslogs"

dest_cloudwatch_driver(lc) if {
	lc.logDriver == "awsfirelens"
	lower(lc.options.Name) in dest_firelens_cloudwatch
}

dest_driver_label(lc) := sprintf("awsfirelens with output %s", [lc.options.Name]) if {
	lc.logDriver == "awsfirelens"
	is_string(lc.options.Name)
} else := "awsfirelens with no output Name option" if {
	lc.logDriver == "awsfirelens"
} else := sprintf("%v", [lc.logDriver])

dest_findings contains {"address": rc.address, "kind": "ecs-log-driver", "what": sprintf("container %s log driver %s", [c.name, dest_driver_label(lc)])} if {
	some rc in dest_changes("aws_ecs_task_definition")
	some c in dest_containers(rc)
	lc := c.logConfiguration
	is_object(lc)
	not dest_cloudwatch_driver(lc)
}

# Lambda telemetry layers: each layer ARN against every telemetry-layers.yml
# row. Layers known only after apply cannot be matched and pass.
dest_layer_vendors(layer) := {row.vendor |
	some row in data.telemetry_layers
	regex.match(row.match, layer)
}

dest_findings contains {"address": rc.address, "kind": "lambda-telemetry", "what": sprintf("Lambda layer %s (%s)", [layer, concat(", ", sort(vendors))])} if {
	some rc in dest_changes("aws_lambda_function")
	some layer in rc.change.after.layers
	is_string(layer)
	vendors := dest_layer_vendors(layer)
	count(vendors) > 0
}

# OpenTelemetry exporter settings (OTLP, Zipkin, Prometheus) all start with
# OTEL_EXPORTER_ (opentelemetry-specification protocol/exporter.md and
# configuration/sdk-environment-variables.md).
dest_otel_prefix := "OTEL_EXPORTER_"

dest_findings contains {"address": rc.address, "kind": "otel-exporter", "what": sprintf("environment variable %s", [name])} if {
	some rc in dest_changes("aws_lambda_function")
	some env in rc.change.after.environment
	some name, _ in env.variables
	startswith(name, dest_otel_prefix)
}

# A variable whose value is unknown at plan time is missing from after, and
# terraform show -json lists its name in after_unknown instead.
dest_findings contains {"address": rc.address, "kind": "otel-exporter", "what": sprintf("environment variable %s", [name])} if {
	some rc in dest_changes("aws_lambda_function")
	some env in rc.change.after_unknown.environment
	is_object(env.variables)
	some name in object.keys(env.variables)
	startswith(name, dest_otel_prefix)
}

dest_findings contains {"address": rc.address, "kind": "otel-exporter", "what": sprintf("container %s environment variable %s", [c.name, e.name])} if {
	some rc in dest_changes("aws_ecs_task_definition")
	some c in dest_containers(rc)
	some e in c.environment
	startswith(e.name, dest_otel_prefix)
}

deny contains msg if {
	some f in dest_findings
	not exception_active_exact_kind(dest_rule, f.address, f.kind)
	msg := sprintf("%s: %s, %s (destination kind %s): log content leaves the root's CloudWatch log groups, a disclosure to whoever operates the target. Remove it, or add an exceptions.yml entry for %s with this exact address as scope, destination.kind %s and a destination block (%s)", [f.address, dest_root, f.what, f.kind, dest_rule, f.kind, dest_rule])
}

# A container_definitions value unknown at plan time hides every container's
# log configuration, so it fails closed under the ecs-log-driver kind.
deny contains msg if {
	some rc in dest_changes("aws_ecs_task_definition")
	rc.change.after_unknown.container_definitions == true
	not exception_active_exact_kind(dest_rule, rc.address, "ecs-log-driver")
	msg := sprintf("%s: %s, container_definitions is not known at plan time, so no container's log configuration can be checked (destination kind ecs-log-driver). Build the definitions from values known at plan time, or add an exceptions.yml entry for %s with this exact address as scope, destination.kind ecs-log-driver and a destination block (%s)", [rc.address, dest_root, dest_rule, dest_rule])
}

deny contains msg if {
	some rc in dest_changes("aws_lambda_function")
	count([layer | some layer in rc.change.after.layers]) > 0
	not data.telemetry_layers
	msg := sprintf("%s: student-pii root, the function has Lambda layers but data.telemetry_layers is missing, so they cannot be checked for destination kind lambda-telemetry. Pass the list to conftest with --data policy/data/telemetry-layers.yml (%s)", [rc.address, dest_rule])
}

# Bedrock invocation logging to S3 is denied outright, in any student-pii root
# and in the account-baseline root.
dest_bedrock_changes := dest_account_changes("aws_bedrock_model_invocation_logging_configuration")

dest_bedrock_s3 contains {"address": rc.address, "field": "s3_config"} if {
	some rc in dest_bedrock_changes
	some lc in rc.change.after.logging_config
	is_array(lc.s3_config)
	count(lc.s3_config) > 0
}

dest_bedrock_s3 contains {"address": rc.address, "field": "cloudwatch_config.large_data_delivery_s3_config"} if {
	some rc in dest_bedrock_changes
	some lc in rc.change.after.logging_config
	some cw in lc.cloudwatch_config
	is_array(cw.large_data_delivery_s3_config)
	count(cw.large_data_delivery_s3_config) > 0
}

deny contains msg if {
	some b in dest_bedrock_s3
	msg := sprintf("%s: %s, Bedrock invocation logging writes to S3 through %s (destination kind bedrock-s3). Those objects sit outside the log group's data protection policy and retention, so no exceptions.yml entry waives this. Remove the block (%s)", [b.address, dest_root, b.field, dest_rule])
}

# The configuration is one per account and Region, so the account-baseline
# root owns it.
deny contains msg if {
	not acct_baseline_root
	some rc in dest_changes("aws_bedrock_model_invocation_logging_configuration")
	msg := sprintf("%s: student-pii app root, the Bedrock invocation logging configuration belongs to the account-baseline root (psd:root = account-baseline, templates/account-baseline/), since there is one per account and Region. Remove it from this root. No exceptions.yml entry waives this (%s)", [rc.address, dest_rule])
}
