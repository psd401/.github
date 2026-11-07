# ABOUTME: The required tag set is applied through provider default_tags, never per resource.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "District defaults" / 12-cloud-cost.md rule 3: the psd:* tag set is
# applied mechanically via default_tags in the provider block, never per
# resource. Reads the plan JSON's configuration.provider_config, not
# planned_values, so an all-variable tag map still gets checked (the tag
# *keys* must be literal even when values are not).

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

# `tags = var.tags` or `tags = merge(...)` arrives as a single expression with
# only `references`; the keys cannot be checked, so the standard's "tag keys are
# literal" rule is the finding.
deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	some block in provider.expressions.default_tags
	block.tags.references
	msg := sprintf("aws provider config %q sets default_tags.tags from an expression (%v); write the tag keys as a map literal so they can be checked (08-iac.md, Tags)", [name, block.tags.references])
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
