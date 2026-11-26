# ABOUTME: Offline terraform test for the app-key module against a mocked aws provider.
# ABOUTME: Rotation, the inline policy's statements and their conditions, and input validation.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-west-2" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:111122223333:key/k", key_id = "k" }
  }
}

variables {
  name = "demo-dev"
}

run "defaults" {
  command = apply

  assert {
    condition     = aws_kms_key.this.enable_key_rotation && aws_kms_key.this.deletion_window_in_days == 30
    error_message = "rotation on, 30-day deletion window"
  }
  assert {
    condition     = aws_kms_alias.this.name == "alias/demo-dev"
    error_message = "alias/<name>"
  }
  assert {
    condition     = [for s in jsondecode(aws_kms_key.this.policy).Statement : s.Sid] == ["AccountAdministersThroughIam", "CloudWatchLogsForTheAppsLogGroups", "AwsServicesPublishToTheAppsTopicsAndQueues"]
    error_message = "three statements by default"
  }
  assert {
    condition     = jsondecode(aws_kms_key.this.policy).Statement[1].Condition.ArnLike["kms:EncryptionContext:aws:logs:arn"] == ["arn:aws:logs:us-west-2:111122223333:log-group:/aws/lambda/demo-dev*"]
    error_message = "logs may use the key only for the app's own /aws/lambda/<name>* log groups, the bare name included"
  }
  assert {
    condition     = jsondecode(aws_kms_key.this.policy).Statement[1].Principal.Service == "logs.us-west-2.amazonaws.com"
    error_message = "the regional logs principal"
  }
  assert {
    condition     = jsondecode(aws_kms_key.this.policy).Statement[2].Condition.StringEquals["aws:SourceAccount"] == "111122223333"
    error_message = "publishers limited to this account"
  }
  assert {
    condition     = jsondecode(output.use_policy_json).Statement[0].Resource == "arn:aws:kms:us-west-2:111122223333:key/k"
    error_message = "use policy names only this key"
  }
}

run "no_logs_no_publishers" {
  command = apply
  variables {
    log_group_prefixes = []
    publisher_services = []
  }
  assert {
    condition     = length(jsondecode(aws_kms_key.this.policy).Statement) == 1
    error_message = "empty lists drop those statements"
  }
}

run "bad_name" {
  command = plan
  variables {
    name = "Demo_Dev"
  }
  expect_failures = [var.name]
}
