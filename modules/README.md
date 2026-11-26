# Terraform modules

Shared Terraform for PSD apps (standards/08 "Module library"). Each module meets the Checkov checks
apps used to skip, so a repo that uses them writes no `#checkov:skip` for these resources. With the
org baseline (`policy/checkov/baseline.yaml`) a root that calls all five had 46 passed, 0 failed
(checkov 3.4.11, 2026-11-26).

A skip written inside a module does nothing for the app: checkov's plan enrichment reads the
caller's files and leaves `.terraform/` out, so a skip in a module pulled by git ref is never seen
(measured 2026-11-26). That is why these modules meet each check instead of skipping it.

| Module | What it makes | Checks it meets |
|---|---|---|
| `app-key` | One customer-managed key per app per environment, rotation on, alias `alias/<name>`, an inline key policy for the account, CloudWatch Logs (the app's own log groups) and AWS services publishing to the app's topics and queues | CKV_AWS_7, CKV_AWS_33, CKV2_AWS_64; no IAM `*` skips, because the policy isn't an identity policy document |
| `lambda` | ARM64 function, X-Ray, reserved concurrency, env vars on the key, its log group (30 or 90 days, on the key), a dead-letter queue on the key, and one inline policy on the runtime role for those | CKV_AWS_50, 115, 116, 173, 158, 66, 27 |
| `sns-topic` | A topic on the key | CKV_AWS_26 |
| `dynamodb-table` | On-demand table on the key, point-in-time recovery, deletion protection | CKV_AWS_119, CKV_AWS_28 |
| `s3-bucket` | Bucket on the key with a bucket key, versioning, noncurrent-version expiry, multipart abort, no public access, TLS only, access logs to the account's log bucket | CKV_AWS_145, 18, 21, CKV2_AWS_6, 61 |

## Use

Pin by tag, never a branch:

```hcl
module "key" {
  source = "git::https://github.com/psd401/.github.git//modules/app-key?ref=vX.Y.Z"
  name   = "schedule-builder-dev"
}

module "worker" {
  source               = "git::https://github.com/psd401/.github.git//modules/lambda?ref=vX.Y.Z"
  name                 = "schedule-builder-dev-worker"
  role_arn             = aws_iam_role.worker.arn
  kms_key_arn          = module.key.key_arn
  reserved_concurrency = 5
  log_retention_days   = 30
  image_uri            = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
}
```

## What the app still provides

- **The runtime role.** `lambda` adds one inline policy to it (`<name>-function`). Anything else
  the function reads (its table, bucket, secrets) the app grants, with `app-key`'s
  `use_policy_json` for the key.
- **psd-aws-infra services.** The app's app-bootstrap entry lists `kms`, `logs`, `lambda`, `sqs`
  and `xray`, plus `sns`, `dynamodb` or `s3` for those modules.
- **The access-log bucket** for `s3-bucket`: the account's server access log bucket, from
  psd-aws-infra.

## Limits

- `lambda` manages `image_uri`. An app that deploys images outside Terraform keeps its own
  function resource for now; a lifecycle rule can't depend on an input.
- `log_retention_days` takes 30 or 90 only (standards/12 rule 5).
- Every module has an offline `terraform test` (`tests/`), run by `iac-tests.yml`
  `app-modules-test`. They check the module's own settings, not AWS behavior; a real plan and
  apply in an app is the test of the key policy and the role policy.
