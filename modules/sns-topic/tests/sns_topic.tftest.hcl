# ABOUTME: Offline terraform test for the sns-topic module against a mocked aws provider.

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

run "on_the_app_key" {
  command = apply
  variables {
    name        = "demo-dev-alerts"
    kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/k"
  }
  assert {
    condition     = aws_sns_topic.this.kms_master_key_id == "arn:aws:kms:us-west-2:111122223333:key/k"
    error_message = "topic on the app key (CKV_AWS_26)"
  }
}
