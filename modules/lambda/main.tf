# ABOUTME: A Lambda function with what PSD's standards ask of every one: ARM64, X-Ray, reserved
# ABOUTME: concurrency, env vars on the app key, its own encrypted log group and dead-letter queue.

locals {
  log_group = "/aws/lambda/${var.name}"
  role_name = element(split("/", var.role_arn), length(split("/", var.role_arn)) - 1)
  image     = var.image_uri != null
}

# Declared, not auto-created, so retention and the key are set (standards/12 rule 5).
resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# Every function gets a dead-letter queue (CKV_AWS_116; Kris, 2026-11-26). A synchronous
# function's queue never receives a message, and SQS charges per request, so an idle queue
# costs nothing.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  kms_master_key_id         = var.kms_key_arn
}

# What the function itself needs from its role: write its logs, send traces, use its queue and
# the app key. CreateFunction checks the role can send to the queue, so this comes first.
resource "aws_iam_role_policy" "function" {
  name = "${var.name}-function"
  role = local.role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteItsLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.this.arn}:*"
      },
      {
        # X-Ray's trace actions take no resource (Service Authorization Reference, X-Ray).
        Sid      = "SendTraces"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
        Resource = "*"
      },
      {
        Sid      = "SendToItsDeadLetterQueue"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.dlq.arn
      },
      {
        Sid      = "UseTheAppKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  role          = var.role_arn
  architectures = ["arm64"]
  memory_size   = var.memory_size
  timeout       = var.timeout

  package_type     = local.image ? "Image" : "Zip"
  image_uri        = var.image_uri
  filename         = var.filename
  source_code_hash = var.source_code_hash
  handler          = local.image ? null : var.handler
  runtime          = local.image ? null : var.runtime

  dynamic "image_config" {
    for_each = local.image && length(var.image_command) > 0 ? [1] : []
    content {
      command = var.image_command
    }
  }

  reserved_concurrent_executions = var.reserved_concurrency
  kms_key_arn                    = var.kms_key_arn

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  dynamic "environment" {
    for_each = length(var.environment) > 0 ? [1] : []
    content {
      variables = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.this, aws_iam_role_policy.function]
}
