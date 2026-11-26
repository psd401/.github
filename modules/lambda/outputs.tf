# ABOUTME: Outputs of the lambda module.

output "function_name" {
  value = aws_lambda_function.this.function_name
}

output "function_arn" {
  value = aws_lambda_function.this.arn
}

output "invoke_arn" {
  value = aws_lambda_function.this.invoke_arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}

output "dlq_arn" {
  description = "Alarm on this queue's ApproximateNumberOfMessagesVisible."
  value       = aws_sqs_queue.dlq.arn
}

output "dlq_name" {
  value = aws_sqs_queue.dlq.name
}
