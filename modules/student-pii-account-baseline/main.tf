# ABOUTME: Account-level student-pii controls: one data protection policy per Region, a break-glass
# ABOUTME: Unmask role, and an alert on every AssumeRole of it. No Bedrock invocation logging exists.

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  identifiers = concat(var.managed_identifiers, [for c in var.custom_identifiers : c.name])

  # The alert rule and its target live in the topic's Region. The break-glass
  # trust pins aws:RequestedRegion to it too, so every successful AssumeRole is
  # a CloudTrail event in the Region the rule watches.
  alerts_region = split(":", var.alerts_topic_arn)[3]

  baseline_apply_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/${var.baseline_apply_role_name}"
}

# One account policy per Region with scope ALL. The Audit and Deidentify
# statements list the same identifiers, which the service requires and
# account_controls.rego checks at plan time. Custom identifiers are defined in Configuration and
# referenced by bare name. Policy syntax:
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-accountlevel.html
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL-custom-data-identifiers.html
resource "aws_cloudwatch_log_account_policy" "data_protection" {
  for_each = toset(var.regions)

  region      = each.key
  policy_name = "student-pii-data-protection"
  policy_type = "DATA_PROTECTION_POLICY"
  scope       = "ALL"

  policy_document = jsonencode({
    Name    = "student-pii-data-protection"
    Version = "2021-06-01"
    Configuration = {
      CustomDataIdentifier = [for c in var.custom_identifiers : { Name = c.name, Regex = c.regex }]
    }
    Statement = [
      {
        Sid            = "audit-policy"
        DataIdentifier = local.identifiers
        Operation      = { Audit = { FindingsDestination = {} } }
      },
      {
        Sid            = "redact-policy"
        DataIdentifier = local.identifiers
        Operation      = { Deidentify = { MaskConfig = {} } }
      },
    ]
  })
}

# No Bedrock model invocation logging configuration. With none, Bedrock
# stores no invocation content, so the control is that none exists.
# PutModelInvocationLoggingConfiguration rejects a configuration with no S3 or
# CloudWatch destination ("At least one logging config must be specified"),
# so content-off cannot be expressed as a resource. The SCP's
# DenyLogControlTamper (outputs.tf) keeps anyone but the apply role from
# creating one, and templates/account-baseline/README.md ("No invocation
# logging") checks after each apply that none exists.

# The only principal allowed logs:Unmask. Trust is the account itself, gated
# on the caller being the break-glass permission set's role, a caller-set
# source identity, and the alert Region's STS endpoint.
#
# aws:MultiFactorAuthPresent is never present for federated identities (IAM
# User Guide, AWS global condition context keys, read 2026-10-23), so an
# Identity Center session could not meet an MFA condition. The identity
# source enforces MFA at sign-in instead. The ArnLike pattern follows "Custom
# trust policy example" in the IAM Identity Center User Guide (Referencing
# permission sets, read 2026-10-23). Identity Center puts the identity
# source's Region in the role path, except for us-east-1, and a new suffix on
# each re-created role, so both are wildcards. ArnLike wildcards also match
# "/", so a customer role whose path holds AWSReservedSSO_<name>_ would match.
# Whether IAM allows a customer role under /aws-reserved/ is unverified
# (research/student-pii-account-controls.md, Unverified).
resource "aws_iam_role" "breakglass" {
  name                 = var.breakglass_role_name
  description          = "Student-pii break-glass: the only role allowed logs:Unmask. Every AssumeRole alerts the district alerts topic."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PermissionSetAndSourceIdentityRequired"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = ["sts:AssumeRole", "sts:SetSourceIdentity"]
        Condition = {
          ArnLike      = { "aws:PrincipalArn" = "arn:${local.partition}:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_${var.breakglass_permission_set_name}_*" }
          Null         = { "sts:SourceIdentity" = "false" }
          StringEquals = { "aws:RequestedRegion" = local.alerts_region }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "breakglass_unmask" {
  name = "student-pii-unmask"
  role = aws_iam_role.breakglass.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowUnmask"
        Effect   = "Allow"
        Action   = ["logs:Unmask"]
        Resource = [for r in var.regions : "arn:${local.partition}:logs:${r}:${local.account_id}:log-group:*"]
      },
    ]
  })
}

# logs:Unmask only changes what a read returns, so the role also needs the
# reads (GetLogEvents, FilterLogEvents, StartQuery). This managed policy
# grants no Unmask.
resource "aws_iam_role_policy_attachment" "breakglass_read" {
  role       = aws_iam_role.breakglass.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/CloudWatchLogsReadOnlyAccess"
}

# CloudTrail records AssumeRole as a read-only management event, which a rule
# receives only in state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS:
# https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html
#
# requestParameters.roleArn is the ARN as the caller typed it. IAM role names
# are unique regardless of case (IAM API Reference, CreateRole, read
# 2026-10-23), so the match ignores case. Syntax from "Comparison operators
# for use in event patterns in Amazon EventBridge" (read 2026-10-23):
# https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
resource "aws_cloudwatch_event_rule" "breakglass_assumed" {
  region      = local.alerts_region
  name        = "student-pii-breakglass-assumed"
  description = "Every AssumeRole of the student-pii break-glass role."
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource       = ["sts.amazonaws.com"]
      eventName         = ["AssumeRole"]
      requestParameters = { roleArn = [{ equals-ignore-case = aws_iam_role.breakglass.arn }] }
    }
  })
}

resource "aws_cloudwatch_event_target" "breakglass_assumed" {
  region = local.alerts_region
  rule   = aws_cloudwatch_event_rule.breakglass_assumed.name
  arn    = var.alerts_topic_arn
}
