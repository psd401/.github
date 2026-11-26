# ABOUTME: Outputs of the dynamodb-table module.

output "arn" {
  value = aws_dynamodb_table.this.arn
}

output "name" {
  value = aws_dynamodb_table.this.name
}
