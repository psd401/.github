# ABOUTME: Offline terraform test for the dynamodb-table module against a mocked aws provider.

mock_provider "aws" {
}

variables {
  name        = "demo-dev-items"
  kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/k"
  hash_key    = "pk"
  attributes  = { pk = "S" }
}

run "defaults" {
  command = apply
  assert {
    condition     = aws_dynamodb_table.this.server_side_encryption[0].enabled && aws_dynamodb_table.this.server_side_encryption[0].kms_key_arn == var.kms_key_arn
    error_message = "on the app key (CKV_AWS_119)"
  }
  assert {
    condition     = aws_dynamodb_table.this.point_in_time_recovery[0].enabled
    error_message = "point-in-time recovery (CKV_AWS_28)"
  }
  assert {
    condition     = aws_dynamodb_table.this.billing_mode == "PAY_PER_REQUEST" && aws_dynamodb_table.this.deletion_protection_enabled
    error_message = "on demand, deletion protection on"
  }
  assert {
    condition     = length(aws_dynamodb_table.this.ttl) == 0
    error_message = "no TTL unless asked"
  }
}

run "bad_attribute_type" {
  command = plan
  variables {
    attributes = { pk = "STRING" }
  }
  expect_failures = [var.attributes]
}

run "attribute_no_key_uses" {
  command = plan
  variables {
    attributes = { pk = "S", gsi1pk = "S" }
  }
  expect_failures = [var.attributes]
}

run "range_key_missing_from_attributes" {
  command = plan
  variables {
    range_key = "sk"
  }
  expect_failures = [var.attributes]
}
