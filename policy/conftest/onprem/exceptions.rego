# ABOUTME: Shared helper for the onprem package; mirrors aws/exceptions.rego.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package onprem

# Shared helper: is there an active, unexpired exceptions.yml entry that covers
# a given rule and scope? Mirrors policy/conftest/aws/exceptions.rego exactly
# (same field names, same matching rules) so both packages read
# `--data exceptions.yml` the same way. Schema: schemas/iac/exceptions.schema.json,
# standards/08-iac.md 'Exceptions file' (reused here per 15-onprem-platform.md's "Builds on"
# note).
#
# exceptions.yml is passed to conftest with --data <path>/exceptions.yml;
# conftest merges that file's top-level keys straight into `data`, so its
# "exceptions:" list lands at data.exceptions, per README.md's invocation in
# this directory.

today_str := sprintf("%04d-%02d-%02d", [y, m, d]) if {
	y := time.date(time.now_ns())[0]
	m := time.date(time.now_ns())[1]
	d := time.date(time.now_ns())[2]
}

not_expired(entry) if {
	entry.expires == "none"
}

not_expired(entry) if {
	entry.expires != "none"
	entry.expires >= today_str
}

# scope_match: exact match, or the entry's scope is a prefix of the scope
# being checked (covers a whole service family, e.g. a compose project).
scope_match(entry_scope, scope) if {
	entry_scope == scope
}

scope_match(entry_scope, scope) if {
	entry_scope != scope
	startswith(scope, entry_scope)
}

# rule_id matches either the entry's id (short slug) or an exact match of its
# "standard" field, e.g. "15-onprem-platform.md#restart-policy". Callers pass
# the full "<file>.md#<anchor>" string, as the aws package's callers do: a
# substring match let an entry citing another standard file, or a longer
# anchor, suppress a finding.
rule_id_match(entry, rule_id) if {
	entry.id == rule_id
}

rule_id_match(entry, rule_id) if {
	entry.standard == rule_id
}

exception_active(rule_id, scope) if {
	some entry in data.exceptions
	entry.status == "active"
	rule_id_match(entry, rule_id)
	scope_match(entry.scope, scope)
	not_expired(entry)
}

# exception_active_exact: the entry's standard equals rule_id and its scope
# equals the scope exactly. No prefix scope and no id match, so one entry
# waives one scope under one standard.
exception_active_exact(rule_id, scope) if {
	some entry in data.exceptions
	entry.status == "active"
	entry.standard == rule_id
	entry.scope == scope
	not_expired(entry)
}
