# ABOUTME: Deleting or replacing a stateful resource needs an active exceptions.yml entry.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "Stateful resources": a plan that deletes or replaces a stateful
# resource needs explicit human approval, recorded as an active
# exceptions.yml entry (standards/08-iac.md#stateful-resource-change), not
# just a PR approval conftest can't see.

stateful_types := {
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_rds_cluster_instance",
	"aws_s3_bucket",
	"aws_dynamodb_table",
	"aws_efs_file_system",
	"aws_ebs_volume",
	"aws_elasticache_replication_group",
}

destructive(rc) if {
	"delete" in rc.change.actions
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in stateful_types
	destructive(rc)
	not exception_active("08-iac.md#stateful-resource-change", rc.address)
	msg := sprintf("%s (%s) is deleted or replaced by this plan with no active exceptions.yml entry for 08-iac.md#stateful-resource-change", [rc.address, rc.type])
}
