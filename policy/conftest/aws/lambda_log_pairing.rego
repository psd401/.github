# ABOUTME: Every Lambda function needs an explicitly declared, matching log group.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 5: Lambda log groups are declared explicitly, not
# auto-created, so retention (log_retention.rego) can be set on them. Every
# aws_lambda_function needs a matching aws_cloudwatch_log_group named
# "/aws/lambda/<function_name>".

declared_log_group_names := {name |
	some rc in input.resource_changes
	rc.type == "aws_cloudwatch_log_group"
	name := rc.change.after.name
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	some action in rc.change.actions
	action in {"create", "update"}
	fn_name := rc.change.after.function_name
	expected := sprintf("/aws/lambda/%s", [fn_name])
	not expected in declared_log_group_names
	msg := sprintf("%s has no matching aws_cloudwatch_log_group named %q; Lambda log groups must be declared explicitly, not left to auto-create with no retention", [rc.address, expected])
}
