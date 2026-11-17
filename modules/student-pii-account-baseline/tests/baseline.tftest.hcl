# ABOUTME: Offline terraform test for the student-pii account baseline, run against a mocked aws provider:
# ABOUTME: controls, the SCP output, and input validation in the module and templates/account-baseline.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  # templates/account-baseline looks up the alerts topic by name.
  mock_data "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111122223333:district-alerts"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111122223333:role/district-breakglass-unmask"
    }
  }
}

variables {
  regions = ["us-west-2", "us-east-1"]
  managed_identifiers = [
    "arn:aws:dataprotection::aws:data-identifier/Name",
    "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
    "arn:aws:dataprotection::aws:data-identifier/Address",
  ]
  custom_identifiers = [
    { name = "StudentId", regex = "[Ss]tudent.?[Ii][Dd].{0,4}[0-9]{6,9}" },
  ]
  breakglass_role_name           = "district-breakglass-unmask"
  breakglass_permission_set_name = "StudentPiiBreakGlass"
  baseline_apply_role_name       = "psd-deploy-account-baseline-prod"
  alerts_topic_arn               = "arn:aws:sns:us-west-2:111122223333:district-alerts"

  # Inputs of templates/account-baseline, for the template_ runs.
  account_alias      = "nonprod"
  owner              = "iac-team"
  alerts_topic_name  = "district-alerts"
  deploy_role_prefix = "psd-deploy"
  student_pii = {
    regions                        = ["us-west-2"]
    breakglass_role_name           = "district-breakglass-unmask"
    breakglass_permission_set_name = "StudentPiiBreakGlass"
    custom_identifiers             = [{ name = "StudentId", regex = "[0-9]{6}" }]
  }
}

run "one_account_policy_per_region" {
  assert {
    condition     = toset(keys(aws_cloudwatch_log_account_policy.data_protection)) == toset(var.regions)
    error_message = "Expected exactly one account data protection policy per Region in var.regions."
  }

  assert {
    condition = alltrue([
      for region, policy in aws_cloudwatch_log_account_policy.data_protection :
      policy.region == region && policy.policy_type == "DATA_PROTECTION_POLICY" && policy.scope == "ALL"
    ])
    error_message = "Each account policy must be a DATA_PROTECTION_POLICY with scope ALL in its own Region."
  }

  assert {
    condition = alltrue([
      for policy in aws_cloudwatch_log_account_policy.data_protection : jsonencode([
        for statement in jsondecode(policy.policy_document).Statement :
        [keys(statement.Operation)[0], statement.DataIdentifier]
        ]) == jsonencode([
        ["Audit", concat(var.managed_identifiers, ["StudentId"])],
        ["Deidentify", concat(var.managed_identifiers, ["StudentId"])],
      ])
    ])
    error_message = "The Audit and Deidentify statements must list the same identifiers: every managed ARN and every custom name."
  }

  assert {
    condition = alltrue([
      for policy in aws_cloudwatch_log_account_policy.data_protection :
      jsonencode(jsondecode(policy.policy_document).Configuration.CustomDataIdentifier) == jsonencode([
        { Name = "StudentId", Regex = "[Ss]tudent.?[Ii][Dd].{0,4}[0-9]{6,9}" },
      ])
    ])
    error_message = "Custom identifiers must appear as Configuration.CustomDataIdentifier entries with Name and Regex."
  }
}

# The root passes cloud.aws.student_pii.managed_identifiers, which is null when the
# environment file omits it. The module's three defaults must apply then.
run "null_managed_identifiers_use_the_defaults" {
  variables {
    managed_identifiers = null
  }

  assert {
    condition = alltrue([
      for policy in aws_cloudwatch_log_account_policy.data_protection :
      jsonencode(jsondecode(policy.policy_document).Statement[0].DataIdentifier) == jsonencode([
        "arn:aws:dataprotection::aws:data-identifier/Name",
        "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
        "arn:aws:dataprotection::aws:data-identifier/Address",
        "StudentId",
      ])
    ])
    error_message = "A null managed_identifiers must fall back to the three default managed identifier ARNs."
  }
}

run "breakglass_trust_requires_permission_set_and_source_identity" {
  assert {
    condition     = aws_iam_role.breakglass.name == var.breakglass_role_name
    error_message = "The break-glass role must be named var.breakglass_role_name."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role.breakglass.assume_role_policy).Statement :
      statement.Effect == "Allow"
      && toset(statement.Action) == toset(["sts:AssumeRole", "sts:SetSourceIdentity"])
      && statement.Condition.ArnLike["aws:PrincipalArn"] == "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_StudentPiiBreakGlass_*"
      && statement.Condition.Null["sts:SourceIdentity"] == "false"
      && statement.Condition.StringEquals["aws:RequestedRegion"] == "us-west-2"
      && !contains(keys(statement.Condition), "Bool")
    ])
    error_message = "Every trust statement must require the break-glass permission set's role, a source identity, and the alert rule's Region, and no MFA key, which federated sessions never carry."
  }

  assert {
    condition = jsonencode([
      for statement in jsondecode(aws_iam_role_policy.breakglass_unmask.policy).Statement :
      [statement.Effect, statement.Action]
    ]) == jsonencode([["Allow", ["logs:Unmask"]]])
    error_message = "The break-glass inline policy must allow logs:Unmask and nothing else."
  }
}

run "alert_rule_matches_breakglass_assume_role" {
  assert {
    condition = jsonencode(jsondecode(aws_cloudwatch_event_rule.breakglass_assumed.event_pattern)) == jsonencode({
      detail = {
        eventName         = ["AssumeRole"]
        eventSource       = ["sts.amazonaws.com"]
        requestParameters = { roleArn = [{ equals-ignore-case = "arn:aws:iam::111122223333:role/district-breakglass-unmask" }] }
      }
      detail-type = ["AWS API Call via CloudTrail"]
      source      = ["aws.sts"]
    })
    error_message = "The rule must match CloudTrail AssumeRole events on the break-glass role ARN in any letter case."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.breakglass_assumed.state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    error_message = "CloudTrail logs AssumeRole as read-only, so the rule must receive read-only management events."
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.breakglass_assumed.arn == var.alerts_topic_arn
      && aws_cloudwatch_event_target.breakglass_assumed.rule == aws_cloudwatch_event_rule.breakglass_assumed.name
      && aws_cloudwatch_event_rule.breakglass_assumed.region == "us-west-2"
      && aws_cloudwatch_event_target.breakglass_assumed.region == "us-west-2"
    )
    error_message = "The rule and its target must sit in the alerts topic's Region and target var.alerts_topic_arn."
  }
}

run "scp_denies_the_tamper_set" {
  assert {
    condition = jsonencode([
      for statement in jsondecode(output.scp_json).Statement :
      [statement.Sid, statement.Effect, statement.Action, statement.Resource, statement.Condition]
      ]) == jsonencode([
      ["DenyUnmaskExceptBreakGlass", "Deny", ["logs:Unmask"], "*",
      { ArnNotEquals = { "aws:PrincipalArn" = ["arn:aws:iam::111122223333:role/district-breakglass-unmask"] } }],
      ["DenyLogControlTamper", "Deny", [
        "logs:PutAccountPolicy",
        "logs:DeleteAccountPolicy",
        "bedrock:PutModelInvocationLoggingConfiguration",
        "bedrock:DeleteModelInvocationLoggingConfiguration",
        ], "*",
      { ArnNotEquals = { "aws:PrincipalArn" = ["arn:aws:iam::111122223333:role/psd-deploy-account-baseline-prod"] } }],
      ["DenyBreakGlassTamper", "Deny", [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:UpdateRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
        "iam:TagRole",
        "iam:UntagRole",
        "events:PutRule",
        "events:DeleteRule",
        "events:DisableRule",
        "events:PutTargets",
        "events:RemoveTargets",
        ], [
        "arn:aws:iam::111122223333:role/district-breakglass-unmask",
        "arn:aws:events:us-west-2:111122223333:rule/student-pii-breakglass-assumed",
        ],
      { ArnNotEquals = { "aws:PrincipalArn" = ["arn:aws:iam::111122223333:role/psd-deploy-account-baseline-prod"] } }],
    ])
    error_message = "The SCP must deny logs:Unmask except to the break-glass role. It must deny the log-control writes and the break-glass role and rule writes except to the baseline apply role."
  }
}

# Input validation. Each run sets one bad input and expects only that
# variable's validation to fail.
run "rejects_empty_regions" {
  command = plan

  variables {
    regions = []
  }

  expect_failures = [var.regions]
}

run "rejects_a_malformed_region" {
  command = plan

  variables {
    regions = ["us-west-2", "US-EAST-1"]
  }

  expect_failures = [var.regions]
}

run "rejects_empty_managed_identifiers" {
  command = plan

  variables {
    managed_identifiers = []
  }

  expect_failures = [var.managed_identifiers]
}

run "rejects_empty_custom_identifiers" {
  command = plan

  variables {
    custom_identifiers = []
  }

  expect_failures = [var.custom_identifiers]
}

run "rejects_more_than_ten_custom_identifiers" {
  command = plan

  variables {
    custom_identifiers = [for i in range(11) : { name = "Id${i}", regex = "[0-9]{6}" }]
  }

  expect_failures = [var.custom_identifiers]
}

run "rejects_a_custom_identifier_name_over_128_characters" {
  command = plan

  variables {
    custom_identifiers = [{ name = join("", [for i in range(129) : "a"]), regex = "[0-9]{6}" }]
  }

  expect_failures = [var.custom_identifiers]
}

run "rejects_a_custom_identifier_regex_over_200_characters" {
  command = plan

  variables {
    custom_identifiers = [{ name = "StudentId", regex = join("", [for i in range(201) : "a"]) }]
  }

  expect_failures = [var.custom_identifiers]
}

run "accepts_custom_identifiers_at_the_documented_limits" {
  command = plan

  variables {
    custom_identifiers = [
      for i in range(10) : {
        name  = format("%s%02d", join("", [for j in range(126) : "a"]), i)
        regex = join("", [for j in range(200) : "a"])
      }
    ]
  }

  assert {
    condition     = length(var.custom_identifiers) == 10
    error_message = "Ten custom identifiers with 128-character names and 200-character regexes must pass validation."
  }
}

run "rejects_an_alerts_topic_arn_without_a_region" {
  command = plan

  variables {
    alerts_topic_arn = "arn:aws:sns::111122223333:district-alerts"
  }

  expect_failures = [var.alerts_topic_arn]
}

run "rejects_an_invalid_breakglass_role_name" {
  command = plan

  variables {
    breakglass_role_name           = "district breakglass unmask"
    breakglass_permission_set_name = "StudentPiiBreakGlass"
  }

  expect_failures = [var.breakglass_role_name]
}

# CreatePermissionSet, Name: 1 to 32 characters matching [\w+=,.@-]+.
run "rejects_a_permission_set_name_over_32_characters" {
  command = plan

  variables {
    breakglass_permission_set_name = join("", [for i in range(33) : "p"])
  }

  expect_failures = [var.breakglass_permission_set_name]
}

run "rejects_a_permission_set_name_with_a_wildcard" {
  command = plan

  variables {
    breakglass_permission_set_name = "StudentPii*"
  }

  expect_failures = [var.breakglass_permission_set_name]
}

# templates/account-baseline validates student_pii itself, so a bad
# environment file fails on the root variable. These runs plan the template.
run "template_accepts_student_pii_without_managed_identifiers" {
  module {
    source = "../../templates/account-baseline"
  }

  assert {
    condition     = output.breakglass_role_arn == "arn:aws:iam::111122223333:role/district-breakglass-unmask"
    error_message = "The template must accept a student_pii block that omits managed_identifiers."
  }
}

run "template_rejects_a_malformed_region" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2", "uswest2"]
      breakglass_role_name           = "district-breakglass-unmask"
      breakglass_permission_set_name = "StudentPiiBreakGlass"
      custom_identifiers             = [{ name = "StudentId", regex = "[0-9]{6}" }]
    }
  }

  expect_failures = [var.student_pii]
}

run "template_rejects_an_invalid_breakglass_role_name" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2"]
      breakglass_role_name           = join("", [for i in range(65) : "b"])
      breakglass_permission_set_name = "StudentPiiBreakGlass"
      custom_identifiers             = [{ name = "StudentId", regex = "[0-9]{6}" }]
    }
  }

  expect_failures = [var.student_pii]
}

run "template_rejects_an_invalid_breakglass_permission_set_name" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2"]
      breakglass_role_name           = "district-breakglass-unmask"
      breakglass_permission_set_name = "Student Pii"
      custom_identifiers             = [{ name = "StudentId", regex = "[0-9]{6}" }]
    }
  }

  expect_failures = [var.student_pii]
}

run "template_rejects_empty_managed_identifiers" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2"]
      breakglass_role_name           = "district-breakglass-unmask"
      breakglass_permission_set_name = "StudentPiiBreakGlass"
      managed_identifiers            = []
      custom_identifiers             = [{ name = "StudentId", regex = "[0-9]{6}" }]
    }
  }

  expect_failures = [var.student_pii]
}

run "template_rejects_empty_custom_identifiers" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2"]
      breakglass_role_name           = "district-breakglass-unmask"
      breakglass_permission_set_name = "StudentPiiBreakGlass"
      custom_identifiers             = []
    }
  }

  expect_failures = [var.student_pii]
}

run "template_rejects_a_custom_identifier_regex_over_200_characters" {
  command = plan

  module {
    source = "../../templates/account-baseline"
  }

  variables {
    student_pii = {
      regions                        = ["us-west-2"]
      breakglass_role_name           = "district-breakglass-unmask"
      breakglass_permission_set_name = "StudentPiiBreakGlass"
      custom_identifiers             = [{ name = "StudentId", regex = join("", [for i in range(201) : "a"]) }]
    }
  }

  expect_failures = [var.student_pii]
}

run "rejects_a_permission_set_name_with_a_single_character_wildcard" {
  command = plan

  variables {
    breakglass_permission_set_name = "StudentPii?"
  }

  expect_failures = [var.breakglass_permission_set_name]
}
