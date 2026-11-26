# ABOUTME: Outputs of the s3-bucket module.

output "arn" {
  value = aws_s3_bucket.this.arn
}

output "name" {
  value = aws_s3_bucket.this.id
}
