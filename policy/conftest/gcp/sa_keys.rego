# ABOUTME: No service account keys; keyless workload identity federation only.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package gcp

# 08-iac.md 'Private environment file' GCP section: WIF-pool-plus-attribute-condition-scoped
# provider is the canonical keyless-auth pattern. No service account keys,
# ever.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_service_account_key"
	some action in rc.change.actions
	action == "create"
	msg := sprintf("%s creates a google_service_account_key; GCP auth is WIF-only, no service account keys", [rc.address])
}
