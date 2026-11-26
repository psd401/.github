# ABOUTME: Inputs for the s3-bucket module.

variable "name" {
  description = "Bucket name, <repo>-<env>-<purpose>; psd-aws-infra's boundary allows <repo>-* buckets."
  type        = string
}

variable "kms_key_arn" {
  description = "The app key (modules/app-key key_arn)."
  type        = string
}

variable "access_log_bucket" {
  description = "The account's S3 server access log bucket, from psd-aws-infra. Logs land under <name>/."
  type        = string
}

variable "noncurrent_version_days" {
  description = "Days a replaced or deleted object version is kept (standards/12 rule 6)."
  type        = number
  default     = 30

  validation {
    condition     = var.noncurrent_version_days >= 1
    error_message = "noncurrent_version_days is at least 1."
  }
}

variable "policy_statements" {
  description = "More bucket policy statements, after the module's TLS-only deny."
  type        = list(any)
  default     = []
}
