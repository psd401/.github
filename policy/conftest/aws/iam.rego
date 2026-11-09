# ABOUTME: No aws_iam_user resources; IAM roles only.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "District defaults": no IAM users, roles only.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_user"
	some action in rc.change.actions
	action in {"create", "update"}
	msg := sprintf("%s creates or updates an aws_iam_user; PSD uses IAM roles only, never IAM users", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_access_key"
	some action in rc.change.actions
	action == "create"
	msg := sprintf("%s creates a long-lived IAM access key; agents and CI authenticate via OIDC roles only", [rc.address])
}
