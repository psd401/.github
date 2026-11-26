# ABOUTME: Inputs for the app-key module.

variable "name" {
  description = "<repo>-<env>, for example schedule-builder-dev. The alias is alias/<name>; psd-aws-infra's deploy boundary allows aliases named alias/<repo>-*."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.name))
    error_message = "name is lowercase letters, digits and hyphens: <repo>-<env>."
  }
}

variable "log_group_prefixes" {
  description = "Log group name prefixes CloudWatch Logs may encrypt with this key. The default covers the module library's log groups for the app (/aws/lambda/<name>..., which matches a function named <name> or <name>-<anything>). Empty leaves CloudWatch Logs out of the key policy."
  type        = list(string)
  default     = null
}

variable "publisher_services" {
  description = "AWS service principals that publish to the app's encrypted SNS topics or SQS queues: CloudWatch alarms and EventBridge by default. Limited to this account by aws:SourceAccount."
  type        = list(string)
  default     = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
}
