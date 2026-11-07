# ABOUTME: docker-compose.yml runtime rules for on-prem apps (image pins, restart, port binds, hardening).
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package onprem

# 15-onprem-platform.md §11 (App runtime bones). Input is a
# docker-compose.yml (or the `docker compose config` resolved output), not a
# Terraform plan: conftest reads YAML/JSON directly with its built-in
# parsers, no --input flag needed.

services := input.services

has_published_ports(svc) if {
	count(object.get(svc, "ports", [])) > 0
}

pinned_tag(image) if {
	contains(image, ":")
	not endswith(image, ":latest")
}

# depended_on_healthy: true when some other service's depends_on names this
# service with condition: service_healthy. Only the long-hand map form of
# depends_on carries a condition; the short-hand list form never does, so it
# never makes a service "depended on healthy".
depended_on_healthy(name) if {
	some other_name, other_svc in services
	other_name != name
	depends_on := object.get(other_svc, "depends_on", {})
	is_object(depends_on)
	dep := depends_on[name]
	dep.condition == "service_healthy"
}

# one_shot_ok: 15-onprem-platform.md rule 45's carve-out. A one-shot task
# (schema bootstrap, grant setup) is its own service with restart: "no",
# never hidden inside a long-running container's entrypoint — so restart:
# "no" is allowed when the service publishes no port (nothing network-facing
# depends on it staying up) and nothing else's depends_on waits on it being
# healthy (nothing depends on it staying up either).
one_shot_ok(name, svc) if {
	svc.restart == "no"
	not has_published_ports(svc)
	not depended_on_healthy(name)
}

# Rule: no :latest, and every image has an explicit tag (not left to default
# to :latest implicitly either).
deny contains msg if {
	some name, svc in services
	image := svc.image
	not pinned_tag(image)
	msg := sprintf("service %q uses image %q; images must be pinned to an exact tag, never :latest or an implicit default tag", [name, image])
}

# Rule: restart policy set on every service.
deny contains msg if {
	some name, svc in services
	not svc.restart
	msg := sprintf("service %q sets no restart policy; use restart: unless-stopped", [name])
}

deny contains msg if {
	some name, svc in services
	svc.restart
	svc.restart != "unless-stopped"
	not one_shot_ok(name, svc)
	not exception_active("15-onprem-platform.md#restart-policy", name)
	msg := sprintf("service %q sets restart: %q; PSD's default is unless-stopped (rule-45 one-shot carve-out needs no published ports and no service_healthy dependent, or an active exceptions.yml entry)", [name, svc.restart])
}

# Rule: container hardening is mandatory for every network-facing (published
# port) service: cap_drop: [ALL], no-new-privileges, read_only, non-root uid.
deny contains msg if {
	some name, svc in services
	has_published_ports(svc)
	cap_drop := object.get(svc, "cap_drop", [])
	not "ALL" in cap_drop
	msg := sprintf("service %q publishes ports but does not set cap_drop: [ALL]", [name])
}

deny contains msg if {
	some name, svc in services
	has_published_ports(svc)
	security_opt := object.get(svc, "security_opt", [])
	not "no-new-privileges:true" in security_opt
	msg := sprintf("service %q publishes ports but does not set security_opt: [\"no-new-privileges:true\"]", [name])
}

deny contains msg if {
	some name, svc in services
	has_published_ports(svc)
	object.get(svc, "read_only", false) != true
	msg := sprintf("service %q publishes ports but does not set read_only: true", [name])
}

# Rule: a published port binds a specific host address (15-onprem-platform.md
# §6 rule 22): loopback when the reverse proxy runs on the same VM, or the
# VM's own address when the shared reverse-proxy tier sits on another host.
# A bare "8080:8080", or 0.0.0.0 / ::, listens on every interface. Handles
# both the short string form and the long form `docker compose config` emits.
wildcard_host(host) if host in {"0.0.0.0", "::", "[::]", ""}

port_bound(p) if {
	is_string(p)
	parts := split(p, ":")
	count(parts) >= 3
	host := concat(":", array.slice(parts, 0, count(parts) - 2))
	not wildcard_host(host)
}

port_bound(p) if {
	is_object(p)
	not wildcard_host(object.get(p, "host_ip", ""))
}

deny contains msg if {
	some name, svc in services
	some p in object.get(svc, "ports", [])
	not port_bound(p)
	msg := sprintf("service %q publishes port %v without a specific host address; bind 127.0.0.1 or the VM's own address, never every interface (15-onprem-platform.md rule 22)", [name, p])
}

# `user` must be set, numeric (never a name that depends on the image's
# /etc/passwd), and not UID 0.
non_root_user(user) if {
	regex.match(`^[1-9][0-9]*(:[0-9]+)?$`, user)
}

deny contains msg if {
	some name, svc in services
	has_published_ports(svc)
	user := object.get(svc, "user", "")
	not non_root_user(user)
	msg := sprintf("service %q publishes ports but does not set a non-root numeric user (user: %q)", [name, user])
}
