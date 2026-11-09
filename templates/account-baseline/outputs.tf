# ABOUTME: Outputs of the account-baseline root: the break-glass role ARN, and the SCP JSON that
# ABOUTME: an organization-mode district attaches to this account from the management account.

output "breakglass_role_arn" {
  description = "The only role allowed logs:Unmask in this account."
  value       = module.student_pii_account_baseline.breakglass_role_arn
}

output "scp_json" {
  description = "SCP for guardrail_mode organization. Attach it to this account, not to an OU (README, step 6)."
  value       = module.student_pii_account_baseline.scp_json
}
