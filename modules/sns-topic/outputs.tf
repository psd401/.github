# ABOUTME: Outputs of the sns-topic module.

output "arn" {
  value = aws_sns_topic.this.arn
}

output "name" {
  value = aws_sns_topic.this.name
}
