# student-pii-account-baseline

Account-level student-pii controls, applied once per account by
`templates/account-baseline/`. The template README covers prerequisites,
apply order, the no-invocation-logging check, the SCP and break-glass use.

## Resources

- `aws_cloudwatch_log_account_policy.data_protection`, one per Region in
  `regions`: a `DATA_PROTECTION_POLICY` with scope `ALL`. Its Audit and
  Deidentify statements list the same identifiers: every ARN in
  `managed_identifiers`, then every name in `custom_identifiers`. Custom
  identifiers are defined in `Configuration.CustomDataIdentifier` as
  `{Name, Regex}` and referenced by bare name. The Audit statement has an empty
  `FindingsDestination`.
- `aws_iam_role.breakglass`, named `breakglass_role_name`. Its trust allows
  `sts:AssumeRole` and `sts:SetSourceIdentity` from this account when three
  conditions hold:
  - `aws:PrincipalArn` is the IAM Identity Center role of the
    `breakglass_permission_set_name` permission set (`ArnLike`, with or without a
    Region in the role path).
  - `sts:SourceIdentity` is set.
  - `aws:RequestedRegion` is the alerts topic's Region.

  The trust has no MFA condition: `aws:MultiFactorAuthPresent` is absent from
  federated sessions, so the identity source enforces MFA.
- `aws_iam_role_policy.breakglass_unmask`: `logs:Unmask` on every log group in
  each listed Region, and nothing else.
- `aws_iam_role_policy_attachment.breakglass_read`: the AWS managed
  `CloudWatchLogsReadOnlyAccess`, which grants the reads Unmask applies to and no Unmask.
- `aws_cloudwatch_event_rule.breakglass_assumed` and its target, in the alerts
  topic's Region: CloudTrail `AssumeRole` events on the break-glass role ARN,
  sent to `alerts_topic_arn`. The pattern matches `requestParameters.roleArn`
  with `equals-ignore-case`, because IAM role names are unique regardless of case. The rule state is
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, because CloudTrail records
  AssumeRole as a read-only event.

The module creates no Bedrock model invocation logging configuration. With
none, Bedrock stores no invocation content. AWS rejects a configuration with
every content flag off and no S3 or CloudWatch destination (`ValidationException:
At least one logging config must be specified`), so v1.5.0's content-off
resource could not apply. The control is that no configuration exists: the
SCP's `DenyLogControlTamper` stops any principal but the apply role from
creating one, and the template README's "No invocation logging" check confirms
it after each apply.

## Inputs

| Name | Type | Default |
| --- | --- | --- |
| `regions` | `list(string)` | required |
| `managed_identifiers` | `list(string)` | Name, EmailAddress and Address managed ARNs. Null also means these. |
| `custom_identifiers` | `list(object({name, regex}))` | required |
| `breakglass_role_name` | `string` | required |
| `breakglass_permission_set_name` | `string` | required |
| `baseline_apply_role_name` | `string` | required |
| `alerts_topic_arn` | `string` | required |

Validation blocks reject:

- an empty `regions`, or an entry that is not a lowercase Region code
- an empty `managed_identifiers`
- `custom_identifiers` with no entries or more than 10, a name over 128
  characters, or a regex over 200 characters (CloudWatch Logs limits)
- a `breakglass_role_name` that breaks IAM role name rules
- a `breakglass_permission_set_name` over 32 characters or with a character
  outside `A-Z a-z 0-9 +=,.@_-` (CreatePermissionSet limits), which also
  keeps a wildcard out of the trust pattern
- an `alerts_topic_arn` that is not an SNS topic ARN with a Region

## Outputs

- `breakglass_role_arn`
- `scp_json`: three Deny statements for organization mode. The module never
  applies the SCP.
  - `DenyUnmaskExceptBreakGlass` exempts the break-glass role ARN.
  - `DenyLogControlTamper` covers `logs:PutAccountPolicy`,
    `logs:DeleteAccountPolicy`, `bedrock:PutModelInvocationLoggingConfiguration`
    and `bedrock:DeleteModelInvocationLoggingConfiguration`.
  - `DenyBreakGlassTamper` covers the IAM role writes on the break-glass role
    and the EventBridge rule and target writes on the alert rule.
  - The last two exempt `arn:<partition>:iam::<account>:role/<baseline_apply_role_name>`.

## Tests

```sh
terraform init -backend=false -lockfile=readonly
terraform test
```

`tests/baseline.tftest.hcl` runs offline against `mock_provider "aws"`. CI runs
it in the `baseline-module-test` job of `.github/workflows/psd-ci.yml`. Its
`template_` runs plan `templates/account-baseline/` to test that root's
`student_pii` validation.

## Sources (read 2026-10-23)

- Account-level policy syntax: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-accountlevel.html
- Custom data identifiers: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL-custom-data-identifiers.html
- Bedrock `LoggingConfig`: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_LoggingConfig.html
- Bedrock `GetModelInvocationLoggingConfiguration`: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetModelInvocationLoggingConfiguration.html
- Source identity in trust policies: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
- Read-only CloudTrail events in EventBridge: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html
- `equals-ignore-case` in event patterns: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
- IAM role name rules and case-insensitive uniqueness: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
- SNS topic name rules: https://docs.aws.amazon.com/sns/latest/api/API_CreateTopic.html
