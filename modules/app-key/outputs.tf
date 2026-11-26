# ABOUTME: Outputs of the app-key module: the key, its alias, and a policy granting its use.

output "key_arn" {
  description = "Pass to the other modules' kms_key_arn."
  value       = aws_kms_key.this.arn
}

output "key_id" {
  value = aws_kms_key.this.key_id
}

output "alias_name" {
  value = aws_kms_alias.this.name
}

output "use_policy_json" {
  description = "Identity policy granting use of this key (encrypt, decrypt, data keys). Attach it to a runtime role that reads or writes the app's encrypted data."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "UseTheAppKey"
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
      Resource = aws_kms_key.this.arn
    }]
  })
}
