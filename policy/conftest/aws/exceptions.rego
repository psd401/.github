# ABOUTME: Shared helper: does an active, unexpired exceptions.yml entry cover a rule and scope?
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# Shared helper: is there an active, unexpired exceptions.yml entry that covers
# a given rule and scope? Schema: schemas/iac/exceptions.schema.json (standards/08-iac.md#7).
#
# exceptions.yml is passed to conftest with --data <path>/exceptions.yml;
# conftest merges that file's top-level keys straight into `data`, so its
# "exceptions:" list lands at data.exceptions (a list of entries), per
# README.md's invocation in this directory.

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

# scope_match: exact match, or the entry's scope is a prefix of the resource
# address being checked (covers a whole module or resource family).
scope_match(entry_scope, scope) if {
	entry_scope == scope
}

scope_match(entry_scope, scope) if {
	entry_scope != scope
	startswith(scope, entry_scope)
}

# rule_id matches either the entry's id (short slug) or an exact match of its
# "standard" field, e.g. "08-iac.md#stateful-resource-change". Callers pass
# the full "<file>.md#<anchor>" string, never a bare anchor slug: a loose
# substring match on just the anchor (the prior behavior) let an entry citing
# the wrong standard file still suppress a finding, as long as the anchor
# text happened to appear somewhere in it (#19).
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
# equals the address exactly. No prefix scope and no id match, so one entry
# waives one address under one standard (the student-pii rules use it).
exception_active_exact(rule_id, scope) if {
	some entry in data.exceptions
	exact_entry_active(entry, rule_id, scope)
}

# exception_active_exact_kind: as exception_active_exact, and the entry's
# destination.kind equals kind, so one entry waives one destination kind at
# one address (student_pii_destinations.rego uses it).
exception_active_exact_kind(rule_id, scope, kind) if {
	some entry in data.exceptions
	exact_entry_active(entry, rule_id, scope)
	entry.destination.kind == kind
}

exact_entry_active(entry, rule_id, scope) if {
	entry.status == "active"
	entry.standard == rule_id
	entry.scope == scope
	not_expired(entry)
}
