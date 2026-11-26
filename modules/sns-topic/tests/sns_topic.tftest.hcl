# ABOUTME: Offline terraform test for the sns-topic module against a mocked aws provider.

mock_provider "aws" {
}

run "on_the_app_key" {
  command = apply
  variables {
    name        = "demo-dev-alerts"
    kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/k"
  }
  assert {
    condition     = aws_sns_topic.this.kms_master_key_id == "arn:aws:kms:us-west-2:111122223333:key/k"
    error_message = "topic on the app key (CKV_AWS_26)"
  }
}
