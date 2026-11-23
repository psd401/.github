# ABOUTME: The required tag set is applied through provider default_tags, never per resource.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "District defaults" / 12-cloud-cost.md rule 3: the psd:* tag set is
# applied mechanically via default_tags in the provider block, never per
# resource. Reads the plan JSON's configuration.provider_config first: a
# constant map, or a per-key map of expressions, exposes its keys there. When
# the tags expression has only `references` (Terraform 1.16.5 plans a literal
# map with variable values this way), the keys are checked on each planned
# resource's tags_all instead (see references_only below).

required_tags := {
	"psd:application",
	"psd:environment",
	"psd:owner",
	"psd:managed-by",
	"psd:repo",
	"psd:data-classification",
}

default_tag_keys(provider) := keys if {
	some block in provider.expressions.default_tags
	block.tags.constant_value
	keys := {k | some k, _ in block.tags.constant_value}
}

# A map literal whose values are variables arrives as a map of key -> expression,
# so its keys are still the tag names.
default_tag_keys(provider) := keys if {
	some block in provider.expressions.default_tags
	not block.tags.constant_value
	not block.tags.references
	keys := {k | some k, _ in block.tags}
}

# A tags expression with only `references` hides its keys from configuration.
# Terraform 1.16.5 plans even a literal map that way once any value is a
# variable (`{"psd:application" = var.app, ...}` -> {"references": ["var.app"]}),
# as it does `tags = var.tags` or `merge(...)`.
references_only(provider) if {
	some block in provider.expressions.default_tags
	block.tags.references
}

references_only_provider if {
	some _, provider in input.configuration.provider_config
	provider.name == "aws"
	references_only(provider)
}

# For a references-only provider the check moves to the evaluated tags: every
# aws resource the plan leaves in place (create, update, replace, no-op) that
# has a tags_all attribute must carry every required key. No-op resources are
# included so a steady-state root missing a key cannot pass on a PR that
# creates nothing. A key whose value is unknown at plan (after_unknown) still
# counts as present. A plan with no taggable resources passes: nothing gets
# tagged. All aws resources are checked, not just those under the
# references-only config; a resource missing a required key fails either way.
taggable_change(rc) if {
	rc.mode == "managed"
	endswith(rc.provider_name, "hashicorp/aws")
	is_object(rc.change.after)
}

planned_tag_keys(rc) := known | unknown if {
	known := {k | some k, _ in rc.change.after.tags_all}
	unknown := {k | some k, v in object.get(rc.change.after_unknown, "tags_all", {}); v == true}
}

tags_all_wholly_unknown(rc) if rc.change.after_unknown.tags_all == true

deny contains msg if {
	references_only_provider
	some rc in input.resource_changes
	taggable_change(rc)
	"tags_all" in object.keys(rc.change.after)
	missing := required_tags - planned_tag_keys(rc)
	count(missing) > 0
	msg := sprintf("%s: planned tags_all is missing required tag keys %v; the aws provider's default_tags.tags is an expression, so the keys were checked on each resource (08-iac.md, Tags)", [rc.address, missing])
}

# Fails closed: the provider makes the whole tags_all unknown when the
# resource's own `tags` are not known at plan, so its keys cannot be checked.
deny contains msg if {
	references_only_provider
	some rc in input.resource_changes
	taggable_change(rc)
	tags_all_wholly_unknown(rc)
	msg := sprintf("%s: tags_all is unknown at plan (a per-resource tag value is computed), so the required tag keys cannot be checked; set per-resource tags from known values (08-iac.md, Tags)", [rc.address])
}

missing_tags(provider) := required_tags - default_tag_keys(provider)

deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	not provider.expressions.default_tags
	msg := sprintf("aws provider config %q has no default_tags block; required tags are %v", [name, required_tags])
}

deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	provider.expressions.default_tags
	count(missing_tags(provider)) > 0
	msg := sprintf("aws provider config %q is missing required tag keys in default_tags: %v", [name, missing_tags(provider)])
}
