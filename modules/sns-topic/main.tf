# ABOUTME: An SNS topic encrypted with the app key (CKV_AWS_26), so publishers and subscribers
# ABOUTME: need the key; AWS services publishing to it are allowed in the app-key policy.

resource "aws_sns_topic" "this" {
  name              = var.name
  kms_master_key_id = var.kms_key_arn
}
