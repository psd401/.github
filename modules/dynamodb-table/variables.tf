# ABOUTME: Inputs for the dynamodb-table module.

variable "name" {
  description = "Table name, <repo>-<env>-<purpose>."
  type        = string
}

variable "kms_key_arn" {
  description = "The app key (modules/app-key key_arn)."
  type        = string
}

variable "hash_key" {
  type = string
}

variable "range_key" {
  type    = string
  default = null
}

variable "attributes" {
  description = "Key attributes only (the hash key, the range key and any index keys), name -> S, N or B."
  type        = map(string)

  validation {
    condition     = alltrue([for t in values(var.attributes) : contains(["S", "N", "B"], t)])
    error_message = "Each attribute type is S, N or B."
  }
}

variable "ttl_attribute" {
  description = "Attribute holding an expiry time in epoch seconds, or null for no TTL."
  type        = string
  default     = null
}

variable "deletion_protection" {
  description = "On by default; turn it off only to delete the table on purpose."
  type        = bool
  default     = true
}
