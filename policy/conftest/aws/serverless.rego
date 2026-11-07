# ABOUTME: Non-prod Aurora Serverless v2 scales to zero; every cluster sets min and max.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 7: non-prod Aurora Serverless v2 clusters scale to
# zero (MinCapacity 0); every cluster declares both min and max in code.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_rds_cluster"
	some action in rc.change.actions
	action in {"create", "update"}
	scaling := rc.change.after.serverlessv2_scaling_configuration[_]
	not scaling.min_capacity
	msg := sprintf("%s has a serverlessv2_scaling_configuration with no min_capacity declared", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_rds_cluster"
	some action in rc.change.actions
	action in {"create", "update"}
	scaling := rc.change.after.serverlessv2_scaling_configuration[_]
	not scaling.max_capacity
	msg := sprintf("%s has a serverlessv2_scaling_configuration with no max_capacity declared", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_rds_cluster"
	some action in rc.change.actions
	action in {"create", "update"}
	env := rc.change.after.tags["psd:environment"]
	env != "prod"
	scaling := rc.change.after.serverlessv2_scaling_configuration[_]
	scaling.min_capacity != 0
	msg := sprintf("%s is tagged psd:environment=%q (non-prod) but min_capacity is %v, not 0; non-prod clusters must auto-pause", [rc.address, env, scaling.min_capacity])
}
