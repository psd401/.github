# ABOUTME: conftest verify tests for the onprem package, run against fixtures/onprem.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package onprem

# conftest verify --policy policy/conftest/onprem --data policy/conftest/fixtures/onprem

test_compose_ok_has_no_denials if {
	count(deny) == 0 with input as data.compose_ok
}

test_latest_tag_denied if {
	some msg in deny with input as data.compose_latest
	contains(msg, ":latest")
}

test_missing_hardening_denied if {
	some msg in deny with input as data.compose_no_hardening
	contains(msg, "cap_drop")
}

test_missing_restart_denied if {
	some msg in deny with input as data.compose_no_restart
	contains(msg, "restart")
}

# Rule 45 carve-out: a one-shot task (restart: "no") with no published port
# and no service_healthy dependent passes.
test_one_shot_no_dependents_has_no_denials if {
	count(deny) == 0 with input as data.compose_one_shot_ok
}

# The carve-out doesn't extend to a one-shot task something else waits on
# with condition: service_healthy -- that's not actually a fire-and-forget
# task, so it still needs a real restart policy.
test_one_shot_depended_on_healthy_denied if {
	some msg in deny with input as data.compose_one_shot_depended_on
	contains(msg, "db-init")
}

# Nor to a one-shot task that publishes a port -- something external could
# depend on it staying up even without a compose-level dependency.
test_one_shot_published_port_denied if {
	some msg in deny with input as data.compose_one_shot_published_port
	contains(msg, "db-init")
}

# data.exceptions lookup, same shape as policy/conftest/aws: an active,
# unexpired exceptions.yml entry scoped to the service name suppresses the
# restart-policy denial.
test_restart_with_active_exception_passes if {
	count(deny) == 0 with input as data.compose_restart_exception
}

test_restart_without_exception_denied if {
	some msg in deny with input as data.compose_restart_exception
		with data.exceptions as []
	contains(msg, "restart")
}

test_restart_expired_exception_denied if {
	some msg in deny with input as data.compose_restart_expired_exception
	contains(msg, "restart")
}

# rule_id_match compares the entry's standard to the caller's full
# "<file>.md#<anchor>" string for equality, as aws/exceptions.rego does.
test_rule_id_substring_no_longer_matches if {
	not rule_id_match({"id": "restart-worker", "standard": "15-onprem-platform.md#restart-policy-extra"}, "15-onprem-platform.md#restart-policy")
}

test_restart_exception_citing_wrong_standard_file_still_denied if {
	some msg in deny with input as data.compose_restart_exception
		with data.exceptions as [{
			"id": "restart-wrong-file",
			"standard": "08-iac.md#restart-policy",
			"scope": "worker",
			"status": "active",
			"expires": "none",
		}]
	contains(msg, "restart")
}

exact_entry(scope) := {
	"id": "restart-worker", "standard": "15-onprem-platform.md#restart-policy",
	"scope": scope, "status": "active", "expires": "none",
}

test_exact_accepts_exact_entry if {
	exception_active_exact("15-onprem-platform.md#restart-policy", "worker")
		with data.exceptions as [exact_entry("worker")]
}

test_exact_rejects_prefix_scope if {
	not exception_active_exact("15-onprem-platform.md#restart-policy", "worker-2")
		with data.exceptions as [exact_entry("worker")]
}

# 15-onprem-platform.md §6 rule 22: a published port binds a specific host
# address (loopback, or the VM's own address for a reverse proxy on another
# host), never every interface.
test_unbound_published_port_denied if {
	some msg in deny with input as data.compose_unbound_port
	contains(msg, "host address")
}

test_wildcard_published_port_denied if {
	some msg in deny with input as data.compose_wildcard_port
	contains(msg, "host address")
}

test_long_form_bound_port_has_no_denials if {
	count(deny) == 0 with input as data.compose_long_form_bound
}
