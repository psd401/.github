# ABOUTME: Account-baseline root: applies modules/student-pii-account-baseline once per account,
# ABOUTME: wiring it to cloud.aws.student_pii and the district alerts topic.

data "aws_sns_topic" "alerts" {
  name = var.alerts_topic_name
}

# In a repo created from this template, replace the relative source with
# git::https://github.com/psd401/.github.git//modules/student-pii-account-baseline?ref=<commit-sha>
module "student_pii_account_baseline" {
  source = "../../modules/student-pii-account-baseline"

  regions                        = var.student_pii.regions
  managed_identifiers            = var.student_pii.managed_identifiers
  custom_identifiers             = var.student_pii.custom_identifiers
  breakglass_role_name           = var.student_pii.breakglass_role_name
  breakglass_permission_set_name = var.student_pii.breakglass_permission_set_name
  baseline_apply_role_name       = "${var.deploy_role_prefix}-account-baseline-${var.account_alias}"
  alerts_topic_arn               = data.aws_sns_topic.alerts.arn
}
