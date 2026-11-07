# ABOUTME: No publicly accessible databases in any tier.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 11: no publicly accessible databases, in any tier.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_db_instance"
	some action in rc.change.actions
	action in {"create", "update"}
	rc.change.after.publicly_accessible == true
	msg := sprintf("%s sets publicly_accessible = true; no database may be publicly accessible, in any tier", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_rds_cluster_instance"
	some action in rc.change.actions
	action in {"create", "update"}
	rc.change.after.publicly_accessible == true
	msg := sprintf("%s sets publicly_accessible = true; no database may be publicly accessible, in any tier", [rc.address])
}
