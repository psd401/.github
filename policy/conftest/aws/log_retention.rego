# ABOUTME: Every CloudWatch log group sets explicit, finite retention.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 5 / 08-iac.md: every log group has explicit,
# non-infinite retention.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_cloudwatch_log_group"
	some action in rc.change.actions
	action in {"create", "update"}
	not rc.change.after.retention_in_days
	msg := sprintf("%s has no retention_in_days set (unset means infinite retention)", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_cloudwatch_log_group"
	rc.change.after.retention_in_days == 0
	msg := sprintf("%s sets retention_in_days to 0, which CloudWatch treats as never-expire; set an explicit value", [rc.address])
}
