# ABOUTME: One customer-managed KMS key per app per environment (standards/12 rule 5, 08 "Module
# ABOUTME: library"): rotation on, an inline key policy, and the services an app's resources need.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  arn     = data.aws_partition.current.partition
  region  = data.aws_region.current.region

  log_group_prefixes = var.log_group_prefixes == null ? ["/aws/lambda/${var.name}-"] : var.log_group_prefixes

  # The policy is written inline, not as an aws_iam_policy_document: Resource "*" in a key policy
  # means this key, and Checkov's identity-policy checks (CKV_AWS_109/111/356) can't tell the two
  # apart, which is why every app skipped them (KMS developer guide, "Key policies").
  statements = concat(
    [{
      Sid       = "AccountAdministersThroughIam"
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.arn}:iam::${local.account}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }],
    length(local.log_group_prefixes) == 0 ? [] : [{
      Sid       = "CloudWatchLogsForTheAppsLogGroups"
      Effect    = "Allow"
      Principal = { Service = "logs.${local.region}.amazonaws.com" }
      Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
      Resource  = "*"
      Condition = {
        ArnLike = {
          "kms:EncryptionContext:aws:logs:arn" = [
            for p in local.log_group_prefixes : "arn:${local.arn}:logs:${local.region}:${local.account}:log-group:${p}*"
          ]
        }
      }
    }],
    length(var.publisher_services) == 0 ? [] : [{
      Sid       = "AwsServicesPublishToTheAppsTopicsAndQueues"
      Effect    = "Allow"
      Principal = { Service = var.publisher_services }
      Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
      Resource  = "*"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account } }
    }],
  )
}

resource "aws_kms_key" "this" {
  description             = "${var.name}: the app's customer-managed key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = jsonencode({ Version = "2012-10-17", Statement = local.statements })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}
