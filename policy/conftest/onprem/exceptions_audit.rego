# ABOUTME: Fails on exceptions.yml entries that are expired or not active (on-prem repos).
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package exceptions_audit

# 08-iac.md "Exceptions file": an entry with a past `expires` date or a status
# other than `active` fails CI until it is renewed or removed. The onprem package's
# exception_active helper only ignores such entries; this package makes them a
# finding in their own right so a stale file cannot sit unnoticed.
#
# Lives in its own package so `conftest verify` tests in package aws, which
# share fixture data that deliberately contains an expired entry, are not
# affected. CI runs with --all-namespaces, which evaluates this package.

today_str := sprintf("%04d-%02d-%02d", [y, m, d]) if {
	y := time.date(time.now_ns())[0]
	m := time.date(time.now_ns())[1]
	d := time.date(time.now_ns())[2]
}

deny contains msg if {
	some entry in data.exceptions
	entry.status != "active"
	msg := sprintf("exceptions.yml entry %q has status %q; only active entries may stay in the file (08-iac.md, Exceptions file)", [entry.id, entry.status])
}

deny contains msg if {
	some entry in data.exceptions
	entry.expires != "none"
	entry.expires < today_str
	msg := sprintf("exceptions.yml entry %q expired on %s; renew it with a new approval or remove it (08-iac.md, Exceptions file)", [entry.id, entry.expires])
}
