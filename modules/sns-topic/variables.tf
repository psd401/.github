# ABOUTME: Inputs for the sns-topic module.

variable "name" {
  description = "Topic name, <repo>-<env>-<purpose>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,254}[a-z0-9]$", var.name))
    error_message = "name is lowercase letters, digits and hyphens."
  }
}

variable "kms_key_arn" {
  description = "The app key (modules/app-key key_arn). CloudWatch alarms and EventBridge can publish because the app-key policy allows them."
  type        = string
}
