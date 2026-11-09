# ABOUTME: Partial S3 backend for the account-baseline root. CI writes backend.hcl (bucket, key,
# ABOUTME: region) with scripts/iac/resolve_env_file.py, so each account keeps its own state.
#
# Locally, run the same script with --backend-out, or pass -backend=false to
# validate. backend.hcl is gitignored. The state key is
# account-baseline/<environment>/terraform.tfstate, one per account.
terraform {
  backend "s3" {
    use_lockfile = true
  }
}
