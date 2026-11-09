# Account baseline (student-pii account controls)

Apply this root once per AWS account that runs student-pii workloads. It calls
`modules/student-pii-account-baseline/`, which creates the account controls of
08-iac.md#student-pii-account-posture:

| Control | Resource | Checked at plan time by |
| --- | --- | --- |
| Account data protection policy, scope ALL, one per Region in `cloud.aws.student_pii.regions` | `aws_cloudwatch_log_account_policy.data_protection` | `account_controls.rego` |
| Bedrock invocation logging with text, image, embedding and video delivery off, no S3 or CloudWatch destination | `aws_bedrock_model_invocation_logging_configuration.content_off` | `student_pii_logs.rego`, `student_pii_destinations.rego` (audio needs a CLI step, see "Audio flag") |
| Break-glass role, the only principal allowed `logs:Unmask`, trust gated on the break-glass permission set and a source identity | `aws_iam_role.breakglass` | `unmask.rego` |
| EventBridge rule that sends every AssumeRole of the break-glass role to the alerts topic | `aws_cloudwatch_event_rule.breakglass_assumed` | none |
| SCP document for `guardrail_mode: organization` (output `scp_json`, never applied here) | output only | none |

The provider's `default_tags` carry `psd:root = account-baseline`, so every
resource with `tags_all` carries it. The conftest rules in
`policy/conftest/aws/` treat a plan as this root only when every such resource
carries the tag, which tells this root from a student-pii app root, which may
not touch these controls. Keep the tag in `default_tags`, not on single
resources. Tag nothing in this root `psd:data-classification = student-pii`:
the rules treat a plan that does as an app root.

## Names

The SCP and the deploy-role boundaries expect these names. Keep them.

- Repository: `account-baseline`. The state key is `account-baseline/<environment>/terraform.tfstate`.
- GitHub environments: `prod` and `nonprod`, the same as the `cloud.aws.account_alias` keys.
- Plan role: `psd-plan-account-baseline`.
- Apply role: `<oidc.deploy_role_prefix>-account-baseline-<prod|nonprod>`. The SCP exempts only this role from the log-control deny.

## Prerequisites

1. Fill `cloud.aws.student_pii` in the private environment file: `regions`,
   `guardrail_mode`, `breakglass_role_name`, `breakglass_permission_set_name`
   and at least one `custom_identifiers` entry. Run
   `scripts/iac/check_custom_identifiers.py` on it.
2. Confirm a CloudTrail trail records management events in us-west-2.
   EventBridge receives CloudTrail events only through a trail.
3. Allow `events.amazonaws.com` to `sns:Publish` in the alerts topic's policy.
   If the topic uses a customer-managed KMS key, allow EventBridge in the key policy too.
4. Request the apply role with `boundary/deploy-role-boundary.json.tmpl` as its
   permission boundary. Fill in the placeholders its `_comment` names, then remove the
   `_comment` and `_justification` keys (see "Template comment keys").
5. Give the plan role the reads Terraform needs to refresh this root (see "Plan role reads").
6. Request the break-glass permission set from the Identity Center administrator. This is an
   organization change, so Kris approves it. See "Using the break-glass role".

## Inputs

| Variable | Source |
| --- | --- |
| `account_alias` | `TF_VAR_account_alias`, set by `scripts/iac/resolve_env_file.py` |
| `alerts_topic_name` | `TF_VAR_alerts_topic_name`, set by `scripts/iac/resolve_env_file.py` |
| `student_pii` | `TF_VAR_student_pii`, set by `scripts/iac/resolve_env_file.py` from `cloud.aws.student_pii` without its test strings or `guardrail_mode` |
| `deploy_role_prefix` | `TF_VAR_deploy_role_prefix`, set by `scripts/iac/resolve_env_file.py` from `oidc.deploy_role_prefix` |
| `owner` | `psd.auto.tfvars` |

For a local plan, put `student_pii` and `deploy_role_prefix` in a gitignored
`terraform.tfvars`. Never put them in `psd.auto.tfvars`: an `*.auto.tfvars`
value overrides the `TF_VAR_` value CI exports.

The alerts topic is looked up by name in us-west-2, the provider Region. The
alert rule and the break-glass trust both use the topic's Region.

## Apply order

Apply in nonprod first, then in prod. In each account:

1. Open a pull request. The plan job plans this root with the plan role.
2. Review the plan. Apply behind the GitHub environment's protection rule.
3. Set the audio flag in every listed Region (see "Audio flag").
4. If `guardrail_mode` is `organization`, attach the SCP (see "SCP").
5. Plan a student-pii workload in the same account.

Nothing stops a student-pii app root from planning before step 1. Apply this
root first: until then the account has no masking and no break-glass role.

## Audio flag

hashicorp/aws 6.68.0 (the locked version) and 6.70.0 have no argument for
`audioDataDeliveryEnabled`, so no plan-time check sees it. After each apply that creates or changes the Bedrock configuration,
the apply role sets all five flags in each Region:

```sh
aws bedrock put-model-invocation-logging-configuration --region us-west-2 \
  --logging-config '{"textDataDeliveryEnabled":false,"imageDataDeliveryEnabled":false,"embeddingDataDeliveryEnabled":false,"videoDataDeliveryEnabled":false,"audioDataDeliveryEnabled":false}'
```

Repeat for each Region in `cloud.aws.student_pii.regions`. In organization mode
the SCP allows this call only from the apply role.

## SCP

`terraform output -raw scp_json` prints three statements:

- `DenyUnmaskExceptBreakGlass` denies `logs:Unmask` to every principal except the break-glass role.
- `DenyLogControlTamper` denies `logs:PutAccountPolicy`, `logs:DeleteAccountPolicy`,
  `bedrock:PutModelInvocationLoggingConfiguration` and
  `bedrock:DeleteModelInvocationLoggingConfiguration` to every principal except the apply role.
- `DenyBreakGlassTamper` denies writes to the break-glass role and the alert rule to every
  principal except the apply role. On the role it covers `iam:CreateRole`, `iam:DeleteRole`,
  `iam:UpdateRole`, `iam:UpdateAssumeRolePolicy`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:PutRolePermissionsBoundary`,
  `iam:DeleteRolePermissionsBoundary`, `iam:TagRole` and `iam:UntagRole`. On
  `rule/student-pii-breakglass-assumed` in the alerts Region it covers `events:PutRule`,
  `events:DeleteRule`, `events:DisableRule`, `events:PutTargets` and `events:RemoveTargets`.

`aws:PrincipalArn` matches the break-glass role by name. Without the third statement, an
account admin could delete the role and recreate it with a new trust. The new role would
keep the Unmask exemption.

Each exception is an exact role ARN in this account. From the management
account, create the SCP and attach it to this account, not to an OU: in another
account the same ARNs match nothing, so that account's break-glass and apply
roles would be denied too. Attach it after the first apply, because the
exempted roles must exist first.

## Plan role reads

To refresh this root, the plan role needs:

- `sts:GetCallerIdentity`, `sns:ListTopics`, `sns:GetTopicAttributes`, `sns:ListTagsForResource`
- `logs:DescribeAccountPolicies` and `logs:GetDataProtectionPolicy` (without it, `DescribeAccountPolicies` omits data protection policies), `bedrock:GetModelInvocationLoggingConfiguration`
- `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies` on the break-glass role
- `events:DescribeRule`, `events:ListTargetsByRule`, `events:ListTagsForResource` on the alert rule
- `s3:GetObject` and `s3:ListBucket` on the state bucket and key

## Template comment keys

The two policy templates carry `_comment` and `_justification` keys for reviewers. They are not
IAM policy elements. Remove them before you submit a filled-in file:

```sh
jq 'walk(if type == "object" then del(._comment, ._justification) else . end)' <file>
```

## Using the break-glass role

Humans reach the role through one IAM Identity Center permission set. The trust policy requires
three things:

- The caller's role is that permission set's role: `ArnLike` on `aws:PrincipalArn` with
  `.../aws-reserved/sso.amazonaws.com*/AWSReservedSSO_<breakglass_permission_set_name>_*`.
  The trailing wildcard covers the suffix, which changes when Identity Center re-creates the role.
- A source identity.
- The alert Region's STS endpoint.

The trust has no MFA condition. `aws:MultiFactorAuthPresent` is absent from federated sessions
(IAM condition keys reference, read 2026-10-23). Identity Center or its external identity
provider must require MFA at sign-in.

To set up the permission set, the Identity Center administrator does three things after Kris
approves:

1. Create a permission set named `breakglass_permission_set_name`, with a session of 1 hour.
2. Add [breakglass-permission-set-policy.json.tmpl](breakglass-permission-set-policy.json.tmpl)
   as its inline policy, with `<breakglass-role-name>` filled in and the comment keys removed
   (see "Template comment keys").
3. Assign it in this account to the few named people the CIO approves.

A console role switch cannot set a source identity, so the caller uses the CLI.
Follow [docs/runbooks/student-pii-unmask.md](../../docs/runbooks/student-pii-unmask.md).
It sets the ticket id as the source identity, which the alert triage matches.

## Known gaps

- The baseline apply role is exempt from the SCP. A bad change merged to this root still applies.
- In `standalone` mode, or before the SCP is attached, an account admin can change the break-glass
  role. Only the plan-time check in `unmask.rego` stands in the way, and it sees only changes made
  through Terraform.
- The trust cannot check MFA. It relies on the MFA policy of Identity Center or its external
  identity provider (account-controls finding 60).
- The break-glass path depends on Identity Center. During an Identity Center outage, no one can
  unmask. PSD creates no IAM users (08-iac.md, AWS org boundary), so this is accepted.
- Nothing schedules the quarterly drill or checks that it ran.
- Nothing checks that CloudTrail also delivers to a central archive outside this account.

## Validate locally

```sh
terraform init -backend=false
terraform validate
```

The module's own offline tests run with `terraform test` in
`modules/student-pii-account-baseline/`. They also plan this root to test the
validation on `student_pii`.
