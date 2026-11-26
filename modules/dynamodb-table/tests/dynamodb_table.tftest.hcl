# ABOUTME: Offline terraform test for the dynamodb-table module against a mocked aws provider.

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
  name        = "demo-dev-items"
  kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/k"
  hash_key    = "pk"
  attributes  = { pk = "S" }
}

run "defaults" {
  command = apply
  assert {
    condition     = aws_dynamodb_table.this.server_side_encryption[0].enabled && aws_dynamodb_table.this.server_side_encryption[0].kms_key_arn == var.kms_key_arn
    error_message = "on the app key (CKV_AWS_119)"
  }
  assert {
    condition     = aws_dynamodb_table.this.point_in_time_recovery[0].enabled
    error_message = "point-in-time recovery (CKV_AWS_28)"
  }
  assert {
    condition     = aws_dynamodb_table.this.billing_mode == "PAY_PER_REQUEST" && aws_dynamodb_table.this.deletion_protection_enabled
    error_message = "on demand, deletion protection on"
  }
  assert {
    condition     = length(aws_dynamodb_table.this.ttl) == 0
    error_message = "no TTL unless asked"
  }
}

run "bad_attribute_type" {
  command = plan
  variables {
    attributes = { pk = "STRING" }
  }
  expect_failures = [var.attributes]
}
