# ABOUTME: conftest verify tests for the gcp package, run against fixtures/gcp.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package gcp

# conftest verify --policy policy/conftest/gcp --data policy/conftest/fixtures/gcp

test_plan_ok_has_no_denials if {
	count(deny) == 0 with input as data.plan_ok
}

test_service_account_key_denied if {
	some msg in deny with input as data.plan_sa_key
	contains(msg, "WIF-only")
}

test_project_without_prevent_denied if {
	some msg in deny with input as data.plan_project_no_prevent
	contains(msg, "deletion_policy")
}
