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
  description = "The table's key attributes, name -> S, N or B: the hash key and the range key, nothing else. The module makes no secondary indexes yet, and DynamoDB rejects an attribute no key uses."
  type        = map(string)

  validation {
    condition     = alltrue([for t in values(var.attributes) : contains(["S", "N", "B"], t)])
    error_message = "Each attribute type is S, N or B."
  }

  validation {
    condition     = toset(keys(var.attributes)) == toset(compact([var.hash_key, var.range_key]))
    error_message = "attributes names exactly the hash key and the range key."
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
