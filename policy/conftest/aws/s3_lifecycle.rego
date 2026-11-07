# ABOUTME: Versioned S3 buckets need a noncurrent-version expiration rule.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 6: every versioned S3 bucket has a noncurrent-version
# expiration rule, via a matching aws_s3_bucket_lifecycle_configuration.

versioned_buckets := {bucket_ref |
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_versioning"
	rc.change.after.versioning_configuration[_].status == "Enabled"
	bucket_ref := rc.change.after.bucket
}

lifecycle_configs_with_expiration := {bucket_ref |
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_lifecycle_configuration"
	some rule in rc.change.after.rule
	rule.noncurrent_version_expiration
	bucket_ref := rc.change.after.bucket
}

deny contains msg if {
	some bucket in versioned_buckets
	not bucket in lifecycle_configs_with_expiration
	msg := sprintf("S3 bucket %q is versioned but has no aws_s3_bucket_lifecycle_configuration with noncurrent_version_expiration (acknowledged-suppression buckets need an active exceptions.yml entry)", [bucket])
}

abort_incomplete_multipart_buckets := {bucket_ref |
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_lifecycle_configuration"
	some rule in rc.change.after.rule
	rule.abort_incomplete_multipart_upload
	bucket_ref := rc.change.after.bucket
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_lifecycle_configuration"
	not rc.change.after.bucket in abort_incomplete_multipart_buckets
	not exception_active("12-cloud-cost.md#s3-lifecycle", rc.address)
	msg := sprintf("%s has no abort-incomplete-multipart-upload rule", [rc.address])
}
