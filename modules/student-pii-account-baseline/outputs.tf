# ABOUTME: Outputs of the student-pii account baseline: the break-glass role ARN and the SCP
# ABOUTME: document an organization-mode district attaches to this account. The module never applies it.

output "breakglass_role_arn" {
  description = "ARN of the break-glass role, the only principal allowed logs:Unmask."
  value       = aws_iam_role.breakglass.arn
}

output "scp_json" {
  description = "SCP for guardrail_mode organization. Attach it to this account from the management account. It names this account's role ARNs, so do not attach it to an OU that holds other accounts."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnmaskExceptBreakGlass"
        Effect    = "Deny"
        Action    = ["logs:Unmask"]
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = [aws_iam_role.breakglass.arn] } }
      },
      {
        Sid    = "DenyLogControlTamper"
        Effect = "Deny"
        Action = [
          "logs:PutAccountPolicy",
          "logs:DeleteAccountPolicy",
          "bedrock:PutModelInvocationLoggingConfiguration",
          "bedrock:DeleteModelInvocationLoggingConfiguration",
        ]
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = [local.baseline_apply_role_arn] } }
      },
      # aws:PrincipalArn matches the break-glass role by name, so a role deleted
      # and recreated under that name would inherit the Unmask exemption. Only
      # the apply role may write the role, its policies and trust, or the alert rule.
      {
        Sid    = "DenyBreakGlassTamper"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary",
          "iam:TagRole",
          "iam:UntagRole",
          "events:PutRule",
          "events:DeleteRule",
          "events:DisableRule",
          "events:PutTargets",
          "events:RemoveTargets",
        ]
        Resource = [
          aws_iam_role.breakglass.arn,
          "arn:${local.partition}:events:${local.alerts_region}:${local.account_id}:rule/${aws_cloudwatch_event_rule.breakglass_assumed.name}",
        ]
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = [local.baseline_apply_role_arn] } }
      },
    ]
  })
}
