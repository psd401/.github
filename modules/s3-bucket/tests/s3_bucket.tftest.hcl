# ABOUTME: Offline terraform test for the s3-bucket module against a mocked aws provider.
# ABOUTME: Key and bucket key, versioning, lifecycle, public access block, TLS-only policy, access logs.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-west-2" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:111122223333:key/k", key_id = "k" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-west-2:111122223333:demo-dev-worker-dlq" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-west-2:111122223333:log-group:/aws/lambda/demo-dev-worker" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::demo-dev-data", id = "demo-dev-data" }
  }
}

variables {
  name              = "demo-dev-data"
  kms_key_arn       = "arn:aws:kms:us-west-2:111122223333:key/k"
  access_log_bucket = "psd-s3-access-logs-111122223333-us-west-2"
}

run "defaults" {
  command = apply
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id == var.kms_key_arn
    error_message = "SSE-KMS on the app key (CKV_AWS_145)"
  }
  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.this.rule).bucket_key_enabled
    error_message = "bucket key on"
  }
  assert {
    condition     = aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled"
    error_message = "versioned"
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.this.rule[0].noncurrent_version_expiration[0].noncurrent_days == 30 && aws_s3_bucket_lifecycle_configuration.this.rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 7
    error_message = "standards/12 rule 6 lifecycle"
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.this.block_public_acls && aws_s3_bucket_public_access_block.this.block_public_policy && aws_s3_bucket_public_access_block.this.ignore_public_acls && aws_s3_bucket_public_access_block.this.restrict_public_buckets
    error_message = "no public access"
  }
  assert {
    condition     = aws_s3_bucket_logging.this.target_bucket == var.access_log_bucket && aws_s3_bucket_logging.this.target_prefix == "demo-dev-data/"
    error_message = "access logs to the account log bucket (CKV_AWS_18)"
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.this.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "TLS-only deny first"
  }
}

run "extra_statement" {
  command = apply
  variables {
    policy_statements = [{ Sid = "Extra", Effect = "Deny", Principal = "*", Action = "s3:DeleteBucket", Resource = "arn:aws:s3:::demo-dev-data" }]
  }
  assert {
    condition     = [for s in jsondecode(aws_s3_bucket_policy.this.policy).Statement : s.Sid] == ["TlsOnly", "Extra"]
    error_message = "caller statements follow the TLS deny"
  }
}
