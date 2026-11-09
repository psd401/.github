# ABOUTME: aws provider for the account-baseline root. psd:root = account-baseline marks this root
# ABOUTME: for policy/conftest/aws, which lets only this root manage the account controls.

# Tags come only from default_tags (08-iac.md), never per resource. The module
# sets each resource's Region from cloud.aws.student_pii.regions, so one
# provider block serves every Region.
provider "aws" {
  region = "us-west-2"

  default_tags {
    tags = {
      "psd:application"         = "account-baseline"
      "psd:environment"         = var.account_alias
      "psd:owner"               = var.owner
      "psd:managed-by"          = "terraform"
      "psd:repo"                = "account-baseline"
      "psd:data-classification" = "internal"
      "psd:root"                = "account-baseline"
    }
  }
}
