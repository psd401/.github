# ABOUTME: CloudWatch alarm dimensions must reference resources, not hard-coded IDs.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 10: alarm dimensions reference resources by
# construct (a Terraform reference), never a hard-coded ID string. Reads the
# *configuration* block (pre-apply expressions), since by the time a plan is
# applied the dimension value is already resolved to a literal either way.

deny contains msg if {
	some res in input.configuration.root_module.resources
	res.type == "aws_cloudwatch_metric_alarm"
	dims := res.expressions.dimensions
	dims.constant_value
	msg := sprintf("%s sets dimensions to a literal map instead of a reference to the monitored resource; alarms must point at a real construct (12-cloud-cost.md rule 10)", [res.address])
}
