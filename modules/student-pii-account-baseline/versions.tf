# ABOUTME: Terraform and provider constraints for the student-pii account baseline module.
# ABOUTME: Matches templates/terraform-app (hashicorp/aws ~> 6.0, locked at 6.68.0).
terraform {
  required_version = ">= 1.16"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
