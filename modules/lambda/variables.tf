# ABOUTME: Inputs for the lambda module.

variable "name" {
  description = "Function name, <repo>-<env>-<function>. The log group is /aws/lambda/<name> and the dead-letter queue <name>-dlq."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,59}[a-z0-9]$", var.name))
    error_message = "name is lowercase letters, digits and hyphens, at most 61 characters (the queue adds -dlq; SQS names stop at 80, Lambda at 64)."
  }
}

variable "role_arn" {
  description = "The function's runtime role. The module adds one inline policy to it (<name>-function): its log group, X-Ray, its queue and the app key."
  type        = string
}

variable "kms_key_arn" {
  description = "The app key (modules/app-key key_arn): environment variables, the log group and the queue."
  type        = string
}

variable "reserved_concurrency" {
  description = "Reserved concurrent executions (standards/08: reserved concurrency stays). At least 1; 0 would stop the function."
  type        = number

  validation {
    condition     = var.reserved_concurrency >= 1 && floor(var.reserved_concurrency) == var.reserved_concurrency
    error_message = "reserved_concurrency is a whole number, at least 1."
  }
}

variable "log_retention_days" {
  description = "standards/12 rule 5: 90 in prod, 30 in nonprod and sandbox, 30 at most for a function that can call Bedrock or runs in a student-pii root."
  type        = number

  validation {
    condition     = contains([30, 90], var.log_retention_days)
    error_message = "log_retention_days is 30 or 90 (standards/12 rule 5)."
  }
}

variable "image_uri" {
  description = "Container image URI. Set this, or filename, handler and runtime for a .zip package."
  type        = string
  default     = null
}

variable "image_command" {
  description = "Overrides the image's CMD (image packages only)."
  type        = list(string)
  default     = []
}

variable "filename" {
  description = ".zip package path."
  type        = string
  default     = null
}

variable "source_code_hash" {
  description = "base64 SHA-256 of the .zip, so a new package redeploys."
  type        = string
  default     = null
}

variable "handler" {
  type    = string
  default = null
}

variable "runtime" {
  type    = string
  default = null
}

variable "memory_size" {
  type    = number
  default = 128
}

variable "timeout" {
  type    = number
  default = 30
}

variable "environment" {
  description = "Environment variables, encrypted with the app key. Never a secret's value: pass its ARN or name (standards/08)."
  type        = map(string)
  default     = {}
}
