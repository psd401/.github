# ABOUTME: google_project needs deletion_policy PREVENT; Cloud SQL needs deletion_protection.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package gcp

# 08-iac.md 'Private environment file' GCP section: deletion_policy = "PREVENT" on every
# google_project resource. Extended here to google_sql_database_instance's
# analogous deletion_protection flag, since both guard against an
# accidental destroy of a stateful GCP resource.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_project"
	some action in rc.change.actions
	action in {"create", "update"}
	rc.change.after.deletion_policy != "PREVENT"
	msg := sprintf("%s does not set deletion_policy = \"PREVENT\"", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_sql_database_instance"
	some action in rc.change.actions
	action in {"create", "update"}
	rc.change.after.deletion_protection != true
	msg := sprintf("%s does not set deletion_protection = true", [rc.address])
}
