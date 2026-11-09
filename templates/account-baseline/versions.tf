# ABOUTME: Terraform and provider constraints for the account-baseline root.
# ABOUTME: Same hashicorp/aws constraint as templates/terraform-app, locked at 6.68.0.
terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
