# ABOUTME: Inputs for the account-baseline root. student_pii mirrors cloud.aws.student_pii in the
# ABOUTME: private environment file, and account_alias names the account (prod or nonprod).

variable "account_alias" {
  description = "Which account this state applies to: the cloud.aws.account_alias key, prod or nonprod. CI sets TF_VAR_account_alias. It is also the GitHub environment name and the last part of the apply role name."
  type        = string

  validation {
    condition     = contains(["prod", "nonprod"], var.account_alias)
    error_message = "account_alias must be prod or nonprod. Student-pii workloads never run in sandbox (13-aws-accounts.md rule 1)."
  }
}

variable "owner" {
  description = "Team that owns the account baseline (psd:owner tag)."
  type        = string
}

variable "alerts_topic_name" {
  description = "cloud.aws.alerts_topic_name: the SNS topic in us-west-2 that receives the break-glass alert. CI sets TF_VAR_alerts_topic_name."
  type        = string
}

variable "deploy_role_prefix" {
  description = "oidc.deploy_role_prefix. The SCP exempts <deploy_role_prefix>-account-baseline-<account_alias>, the role that applies this root."
  type        = string
}

variable "student_pii" {
  description = "cloud.aws.student_pii from the private environment file. Keys this root does not use (guardrail_mode, test strings) are ignored."
  type = object({
    regions                        = list(string)
    breakglass_role_name           = string
    breakglass_permission_set_name = string
    managed_identifiers            = optional(list(string))
    custom_identifiers = list(object({
      name  = string
      regex = string
    }))
  })

  # Same rules and sources as modules/student-pii-account-baseline/variables.tf,
  # checked here so a bad environment file fails on this variable.
  validation {
    condition     = length(var.student_pii.regions) > 0 && alltrue([for r in var.student_pii.regions : can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))])
    error_message = "student_pii.regions must list at least one AWS Region, each a lowercase Region code such as us-west-2."
  }

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.student_pii.breakglass_role_name))
    error_message = "student_pii.breakglass_role_name must be an IAM role name: 1 to 64 characters from A-Z, a-z, 0-9 and +=,.@_-."
  }

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,32}$", var.student_pii.breakglass_permission_set_name))
    error_message = "student_pii.breakglass_permission_set_name must be a permission set name: 1 to 32 characters from A-Z, a-z, 0-9 and +=,.@_-."
  }

  validation {
    condition     = var.student_pii.managed_identifiers == null ? true : length(var.student_pii.managed_identifiers) > 0
    error_message = "student_pii.managed_identifiers must list at least one managed data identifier ARN, or be omitted for the three defaults."
  }

  validation {
    condition     = length(var.student_pii.custom_identifiers) > 0 && length(var.student_pii.custom_identifiers) <= 10
    error_message = "student_pii.custom_identifiers must list 1 to 10 entries. CloudWatch Logs allows at most 10 custom data identifiers per policy."
  }

  validation {
    condition = alltrue([
      for c in var.student_pii.custom_identifiers :
      length(c.name) >= 1 && length(c.name) <= 128 && length(c.regex) >= 1 && length(c.regex) <= 200
    ])
    error_message = "Each student_pii.custom_identifiers entry needs a name of 1 to 128 characters and a regex of 1 to 200 characters."
  }
}
