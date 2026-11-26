# ABOUTME: Offline terraform test for the lambda module against a mocked aws provider.
# ABOUTME: ARM64, X-Ray, reserved concurrency, the key, log group, dead-letter queue, role policy, inputs.

mock_provider "aws" {
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-west-2:111122223333:demo-dev-worker-dlq" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-west-2:111122223333:log-group:/aws/lambda/demo-dev-worker" }
  }
}

variables {
  name                 = "demo-dev-worker"
  role_arn             = "arn:aws:iam::111122223333:role/app/demo-dev-worker"
  kms_key_arn          = "arn:aws:kms:us-west-2:111122223333:key/k"
  reserved_concurrency = 2
  log_retention_days   = 30
  filename             = "fn.zip"
  handler              = "app.handler"
  runtime              = "python3.13"
}

run "zip_defaults" {
  command = apply

  assert {
    condition     = tolist(aws_lambda_function.this.architectures) == tolist(["arm64"]) && aws_lambda_function.this.package_type == "Zip"
    error_message = "ARM64 .zip"
  }
  assert {
    condition     = aws_lambda_function.this.tracing_config[0].mode == "Active"
    error_message = "X-Ray active (CKV_AWS_50)"
  }
  assert {
    condition     = aws_lambda_function.this.reserved_concurrent_executions == 2
    error_message = "reserved concurrency set (CKV_AWS_115)"
  }
  assert {
    condition     = aws_lambda_function.this.kms_key_arn == var.kms_key_arn
    error_message = "env vars on the app key (CKV_AWS_173)"
  }
  assert {
    condition     = aws_lambda_function.this.dead_letter_config[0].target_arn == aws_sqs_queue.dlq.arn
    error_message = "dead-letter queue (CKV_AWS_116)"
  }
  assert {
    condition     = aws_sqs_queue.dlq.name == "demo-dev-worker-dlq" && aws_sqs_queue.dlq.kms_master_key_id == var.kms_key_arn
    error_message = "queue named <name>-dlq on the app key"
  }
  assert {
    condition     = aws_cloudwatch_log_group.this.name == "/aws/lambda/demo-dev-worker" && aws_cloudwatch_log_group.this.retention_in_days == 30 && aws_cloudwatch_log_group.this.kms_key_id == var.kms_key_arn
    error_message = "declared log group with retention and the key"
  }
  assert {
    condition     = aws_iam_role_policy.function.role == "demo-dev-worker"
    error_message = "the role's name, not its path"
  }
  assert {
    condition     = [for s in jsondecode(aws_iam_role_policy.function.policy).Statement : s.Sid] == ["WriteItsLogs", "SendTraces", "SendToItsDeadLetterQueue", "UseTheAppKey"]
    error_message = "the function's own permissions"
  }
  assert {
    condition     = length(aws_lambda_function.this.environment) == 0
    error_message = "no environment block when there are no variables"
  }
}

run "image" {
  command = plan
  variables {
    image_uri     = "111122223333.dkr.ecr.us-west-2.amazonaws.com/demo:1"
    image_command = ["app.worker"]
    filename      = null
    handler       = null
    runtime       = null
    environment   = { STAGE = "dev" }
  }
  assert {
    condition     = aws_lambda_function.this.package_type == "Image" && tolist(aws_lambda_function.this.image_config[0].command) == tolist(["app.worker"])
    error_message = "image package with its command"
  }
  assert {
    condition     = aws_lambda_function.this.environment[0].variables["STAGE"] == "dev"
    error_message = "environment variables passed through"
  }
}

run "retention_outside_the_standard" {
  command = plan
  variables {
    log_retention_days = 365
  }
  expect_failures = [var.log_retention_days]
}

run "zero_concurrency" {
  command = plan
  variables {
    reserved_concurrency = 0
  }
  expect_failures = [var.reserved_concurrency]
}

run "zip_without_handler" {
  command = plan
  variables {
    handler = null
  }
  expect_failures = [aws_lambda_function.this]
}
