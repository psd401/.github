# ABOUTME: conftest verify tests for the aws exceptions_audit package.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package exceptions_audit

# conftest verify --policy policy/conftest/aws --data policy/conftest/fixtures/aws
# The shared fixture file carries one deliberately expired entry.

test_expired_entry_is_a_finding if {
	some msg in deny
	contains(msg, "expired on")
}

test_active_unexpired_entries_are_silent if {
	count([m | some m in deny; contains(m, "nat-dev-vpc")]) == 0
}
