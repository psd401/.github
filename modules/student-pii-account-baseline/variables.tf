# ABOUTME: Inputs for the student-pii account baseline: Regions, data identifiers, the break-glass
# ABOUTME: role name, the baseline apply role name the SCP exempts, and the alerts topic ARN.

# The Region pattern matches every Region listed in botocore 1.43.118
# data/partitions.json (read 2026-10-23), such as us-west-2, us-gov-west-1 and
# eusc-de-east-1. It rejects the aws-global style endpoint names.
variable "regions" {
  description = "Regions that get an account-level data protection policy and a Bedrock logging configuration (cloud.aws.student_pii.regions)."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))])
    error_message = "regions must list at least one AWS Region, each a lowercase Region code such as us-west-2."
  }
}

variable "managed_identifiers" {
  description = "AWS managed data identifier ARNs listed in both the Audit and Deidentify statements. Null means these three defaults."
  type        = list(string)
  nullable    = false
  default = [
    "arn:aws:dataprotection::aws:data-identifier/Name",
    "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
    "arn:aws:dataprotection::aws:data-identifier/Address",
  ]

  validation {
    condition     = length(var.managed_identifiers) > 0
    error_message = "managed_identifiers must list at least one managed data identifier ARN. Pass null for the three defaults."
  }
}

# Limits from the CloudWatch Logs User Guide, "Custom data identifiers"
# (read 2026-10-23): at most 10 per data protection policy, names at most 128
# characters, regexes at most 200 characters.
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL-custom-data-identifiers.html
variable "custom_identifiers" {
  description = "District custom data identifiers, 1 to 10. Each name is listed in both statements next to the managed ARNs."
  type = list(object({
    name  = string
    regex = string
  }))

  validation {
    condition     = length(var.custom_identifiers) > 0 && length(var.custom_identifiers) <= 10
    error_message = "custom_identifiers must list 1 to 10 entries. CloudWatch Logs allows at most 10 custom data identifiers per policy."
  }

  validation {
    condition = alltrue([
      for c in var.custom_identifiers :
      length(c.name) >= 1 && length(c.name) <= 128 && length(c.regex) >= 1 && length(c.regex) <= 200
    ])
    error_message = "Each custom identifier needs a name of 1 to 128 characters and a regex of 1 to 200 characters."
  }
}

# IAM API Reference, CreateRole, RoleName (read 2026-10-23): 1 to 64
# characters matching [\w+=,.@-]+.
variable "breakglass_role_name" {
  description = "Name of the only role allowed logs:Unmask (cloud.aws.student_pii.breakglass_role_name)."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.breakglass_role_name))
    error_message = "breakglass_role_name must be an IAM role name: 1 to 64 characters from A-Z, a-z, 0-9 and +=,.@_-."
  }
}

# IAM Identity Center API Reference, CreatePermissionSet, Name (read
# 2026-10-23): 1 to 32 characters matching [\w+=,.@-]+. The pattern also
# keeps * and ? out of the trust's ArnLike value.
variable "breakglass_permission_set_name" {
  description = "Name of the IAM Identity Center permission set whose role may assume the break-glass role (cloud.aws.student_pii.breakglass_permission_set_name)."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,32}$", var.breakglass_permission_set_name))
    error_message = "breakglass_permission_set_name must be a permission set name: 1 to 32 characters from A-Z, a-z, 0-9 and +=,.@_-."
  }
}

variable "baseline_apply_role_name" {
  description = "Name of the role that applies this baseline. The SCP output exempts only this role from the log-control and break-glass tamper denies."
  type        = string
}

# main.tf reads the Region from the fourth ARN field. Topic names follow the
# SNS API Reference, CreateTopic, Name (read 2026-10-23): 1 to 256 characters
# from A-Z, a-z, 0-9, _ and -, and a FIFO topic name ends in .fifo.
variable "alerts_topic_arn" {
  description = "SNS topic that receives the break-glass AssumeRole alert. The alert rule and the break-glass trust use this topic's Region."
  type        = string

  validation {
    condition     = can(regex("^arn:aws(-[a-z]+)*:sns:[a-z]{2,4}(-[a-z]+)+-[0-9]+:[0-9]{12}:([A-Za-z0-9_-]{1,256}|[A-Za-z0-9_-]{1,251}[.]fifo)$", var.alerts_topic_arn))
    error_message = "alerts_topic_arn must be an SNS topic ARN with a Region, such as arn:aws:sns:us-west-2:111122223333:district-alerts."
  }
}
