# ABOUTME: Allowed AWS regions, and one canonical region per application across environments.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 08-iac.md "District defaults": us-west-2 by default; us-east-1 allowed for
# Bedrock-heavy prod workloads and sandboxes. No other region is allowed.

allowed_regions := {"us-west-2", "us-east-1"}

deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	region := provider.expressions.region.constant_value
	not region in allowed_regions
	msg := sprintf("aws provider config %q uses region %q, not in the allowed set %v", [name, region, allowed_regions])
}

deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	not provider.expressions.region.constant_value
	msg := sprintf("aws provider config %q has no literal region (region must be a constant, not a variable, so conftest can enforce the allow-list)", [name])
}

# #24: a single `conftest test` run only sees one environment's plan, so it
# can't directly compare a dev plan's region against the same app's prod
# plan. exceptions.yml is committed once per repo and read by every
# environment's run, so an app that intentionally deviates from the default
# region declares its canonical one there instead (an active entry with
# standard "08-iac.md#region-consistency", scope equal to its
# psd:application tag value, and a "region" field): every environment's plan
# is checked against that one shared declaration, which keeps them in
# agreement without ever comparing two plans at once.
provider_app_tag(provider) := app if {
	some block in provider.expressions.default_tags
	block.tags.constant_value
	app := block.tags.constant_value["psd:application"]
}

declared_region(app) := region if {
	some entry in data.exceptions
	entry.status == "active"
	entry.standard == "08-iac.md#region-consistency"
	entry.scope == app
	not_expired(entry)
	region := entry.region
}

deny contains msg if {
	some name, provider in input.configuration.provider_config
	provider.name == "aws"
	region := provider.expressions.region.constant_value
	app := provider_app_tag(provider)
	expected := declared_region(app)
	region != expected
	msg := sprintf("aws provider config %q uses region %q, but exceptions.yml declares %q as %s's canonical region (08-iac.md#region-consistency); every environment must agree", [name, region, expected, app])
}
