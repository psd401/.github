# policy/conftest

**Status:** Draft v0.3 (2026-10-13), not approved.

Rego policies for the district engineering standards 08-iac.md and
12-cloud-cost.md (internal), run by job 7
(`conftest`) of `reusable-iac-checks.yml` (AWS/GCP) and job 6 of
`reusable-onprem-checks.yml` (Proxmox/compose). Enforced by: those two
reusable workflows, in every consuming repo.

## Layout

```
policy/conftest/
  aws/       # reads a terraform/tofu plan JSON (AWS resources)
  gcp/       # reads the same plan JSON (GCP resources)
  onprem/    # reads a resolved docker-compose config, not a plan
  fixtures/  # sample inputs for conftest verify (see below) -- not CI inputs
```

Each directory is one Rego package (`aws`, `gcp`, `onprem`). Rules use `deny
contains msg if { ... }`; a non-empty `deny` set fails the check.

## Production invocation (what the reusable workflows run)

AWS or GCP, against a saved plan (`tfplan-<run-id>` from the `plan` job,
rendered to JSON with `tofu show -json`):

```sh
conftest test tfplan.json \
  --policy policy/conftest/aws \
  --data exceptions.yml \
  --data student-pii-account.json \
  --data policy/data/telemetry-layers.yml \
  --all-namespaces
```

(`--policy policy/conftest/gcp` for a GCP-platform repo, which needs neither
of the last two `--data` files. `telemetry-layers.yml` is the dated list of
vendor Lambda layers that `student_pii_destinations.rego` reads as
`data.telemetry_layers`. `exceptions.yml` is
the consuming repo's own file at its root, schema in
[schemas/iac/exceptions.schema.json](../../schemas/iac/exceptions.schema.json); see
standards 08-iac.md 'Exceptions file'.
`student-pii-account.json` comes from `scripts/iac/resolve_env_file.py
--student-pii-out` in the plan job: `cloud.aws.student_pii` from the
environment file, which `account_controls.rego` and `unmask.rego` read as
`data.student_pii_account`.)

On-prem, against the compose project's resolved config, not a Terraform
plan. `templates/onprem-app` keeps `docker-compose.yml` at the repo root
(15-onprem-platform.md's layout rule), so that's the path every consuming
repo's CI resolves:

```sh
docker compose config --format json > compose-resolved.json
conftest test compose-resolved.json \
  --policy policy/conftest/onprem \
  --data exceptions.yml \
  --all-namespaces
```

When a repo also has a `terraform/` directory (a Proxmox VM repo, not a
compose-only app repo), its plan JSON is run against an on-prem Terraform
policy package too, if one exists:

```sh
conftest test terraform/tfplan.json \
  --policy policy/conftest/onprem-terraform \
  --data exceptions.yml \
  --all-namespaces
```

No `policy/conftest/onprem-terraform` package exists yet (this PR's scope is
`compose.rego` only), so that step is skipped until one ships -- a repo with
no `terraform/` directory skips it too, by the same existence check.

`--all-namespaces` is required: conftest's default namespace is `main`, and
every policy here lives in a `aws`/`gcp`/`onprem` package, not `main`.

## Exceptions data

`exceptions.yml`'s top-level `exceptions:` key is a list of entries
(id, standard, rule, reason, scope, approved_by, status, expires). conftest's
`--data <file>` merges that file's top-level keys straight into the `data`
document, so the list lands at `data.exceptions` -- every rule that checks
for an exception reads exactly that path (see `aws/exceptions.rego`'s
`exception_active(rule_id, scope)` helper). An entry only counts when
`status == "active"` and `expires` is `"none"` or a date today or later.
Callers pass `rule_id` as the entry's full `standard` string (e.g.
`"08-iac.md#stateful-resource-change"`), matched for exact equality against
`entry.standard` -- never a bare anchor slug matched by substring, which
would let an entry citing the wrong standard file still suppress a finding
(#19).

`exception_active_exact(rule_id, scope)` (same file, and in
`onprem/exceptions.rego`) is the stricter helper the student-pii log rules
use. It matches only when the entry's `standard` equals `rule_id` and its
`scope` equals the resource address exactly. Prefix scopes and `id` matches
do not count, so one entry waives one address under one standard.

`exception_active_exact_kind(rule_id, scope, kind)` also requires the entry's
`destination.kind` to equal the finding's kind. The log destination rules use
it, so an address with two destination kinds needs two entries with distinct
ids.

## Unit tests (`conftest verify`)

```sh
conftest verify --policy policy/conftest/aws     --data policy/conftest/fixtures/aws
conftest verify --policy policy/conftest/gcp     --data policy/conftest/fixtures/gcp
conftest verify --policy policy/conftest/onprem  --data policy/conftest/fixtures/onprem
```

Each `*_test.rego` file sits next to the rules it tests and uses OPA's
`with input as data.<fixture_name>` to swap in a fixture per test case. The
fixture JSON/YAML files under `fixtures/<platform>/` each wrap their content
under a key matching the filename (for example `plan_ok.json` holds
`{"plan_ok": {...}}`), because `--data` on a whole directory merges every
file's top-level keys into one `data` document, and two fixtures sharing a
bare `resource_changes` or `services` key would collide. **These fixtures
are shaped for `conftest verify`, not for a standalone `conftest test` run**
-- they are not drop-in example plans.

`fixtures/aws/exceptions.json` and `fixtures/onprem/exceptions.json` are the
two exceptions to the wrap-under-filename rule: each is unwrapped
(`{"exceptions": [...]}`), matching the real `exceptions.yml` shape, so the
AWS and on-prem unit tests can each exercise both the active-exception and
expired-exception paths against the same helper their production rules
use (`aws/exceptions.rego` and `onprem/exceptions.rego`, respectively).

`aws/exceptions_audit.rego` and `onprem/exceptions_audit.rego` (package
`exceptions_audit`) turn a stale entry into a finding of its own: any entry
whose status is not `active`, or whose `expires` date has passed, fails the
conftest job. The package is separate so the `aws` and `onprem` unit tests,
which share the fixture file with its deliberately expired entry, stay green.

## Rule index

| Platform | File | Rule (standard) |
|---|---|---|
| aws | `tags.rego` | required `psd:*` tags set via `default_tags` (08-iac.md, 12-cloud-cost.md #3) |
| aws | `regions.rego` | region allow-list: us-west-2, us-east-1; one app's environments agree on region, per a shared `exceptions.yml` declaration (08-iac.md) |
| aws | `iam.rego` | no `aws_iam_user`, no long-lived access keys (08-iac.md) |
| aws | `stateful.rego` | delete/replace of a stateful resource needs an active exception (08-iac.md) |
| aws | `nat.rego` | NAT count, gateway endpoints (12-cloud-cost.md #8) |
| aws | `s3_lifecycle.rego` | noncurrent-version expiration + abort-incomplete-multipart on versioned buckets (12-cloud-cost.md #6) |
| aws | `log_retention.rego` | explicit, finite log group retention (12-cloud-cost.md #5) |
| aws | `lambda_log_pairing.rego` | every Lambda has its own declared log group (12-cloud-cost.md #5) |
| aws | `arm64.rego` | ARM64 by default for Lambda/ECS (12-cloud-cost.md #9) |
| aws | `serverless.rego` | Aurora Serverless v2 min/max set, min 0 outside prod (12-cloud-cost.md #7) |
| aws | `alarm_dimensions.rego` | alarm dimensions are references, not literals (12-cloud-cost.md #10) |
| aws | `rds_public.rego` | no `publicly_accessible` databases (12-cloud-cost.md #11) |
| aws | `student_pii_logs.rego` | in a student-pii root, create, update and no-op changes count. Log groups cap retention at 30 days (unless `psd:log-content=none`) and set a customer-managed KMS key. Bedrock invocation logging has text delivery off. No REST method settings, and no `aws_apigatewayv2_stage` default or per-route settings, turn on data tracing. In a student-pii root or the account-baseline root, every Bedrock content-delivery flag (text, image, embedding, video) must be `false`. A null or unknown flag fails (08-iac.md#student-pii-in-logs) |
| aws | `student_pii_destinations.rego` | in a student-pii root, each log destination needs an exceptions.yml entry naming its exact address as scope and its kind as `destination.kind`. Kinds: subscription filter, log destination, account subscription policy, Firehose, log delivery, S3 export target, non-CloudWatch ECS log driver, vendor Lambda layer, OpenTelemetry exporter. An S3 export target is a bucket policy letting the logs service or any principal (`*`) write. An OpenTelemetry variable unknown at plan time counts, and so does an unknown ECS `container_definitions` (kind ecs-log-driver). The account subscription policy also counts in the account-baseline root. Bedrock logging to S3 is denied in a student-pii root or the account-baseline root. A student-pii app root may not hold a Bedrock logging configuration (08-iac.md#student-pii-log-destinations) |
| aws | `account_controls.rego` | in the account-baseline root (every resource change with `tags_all` carries `psd:root = account-baseline`, judged by `before` for a delete; resources without `tags_all` do not count), the data protection policy lists every identifier from `student-pii-account.json` in its Audit and Deidentify statements. A student-pii app root may not change the account policy (08-iac.md#student-pii-account-posture) |
| aws | `unmask.rego` | only the break-glass role named in `student-pii-account.json` is granted `logs:Unmask`, through an inline role policy in the account-baseline root. In that root, the break-glass role's inline policies allow only `logs:Unmask`, and the only managed policy it may hold is `CloudWatchLogsReadOnlyAccess`. Its trust names only account root principals. Every Allow statement requires `ArnLike aws:PrincipalArn` on the IAM Identity Center role of the `breakglass_permission_set_name` permission set, a source identity and `aws:RequestedRegion`. A document or ARN unknown at plan time fails. Create, update and no-op changes count (08-iac.md#student-pii-account-posture) |
| gcp | `sa_keys.rego` | no `google_service_account_key` resources |
| gcp | `deletion_policy.rego` | `deletion_policy = "PREVENT"` on `google_project`; `deletion_protection = true` on `google_sql_database_instance` |
| onprem | `compose.rego` | pinned image tags (no `:latest`), `restart: unless-stopped` (one-shot carve-out below), container hardening (`cap_drop: [ALL]`, `no-new-privileges:true`, `read_only: true`, non-root numeric UID) on any service with published ports |

`compose.rego`'s restart-policy rule carries two ways out, per
15-onprem-platform.md rule 45: a one-shot task (`restart: "no"`) passes
outright when it publishes no port and nothing else's `depends_on` names it
with `condition: service_healthy` (a fire-and-forget bootstrap job, not a
dependency anything waits on); anything else needs an active, unexpired
`exceptions.yml` entry, read via `onprem/exceptions.rego`'s
`exception_active(rule_id, scope)` helper, the same shape as
`aws/exceptions.rego`'s (scope is the service name).

## Known gaps

- The backend-naming (`<state-bucket-prefix>-<account-alias>-<region>`) and
  deploy-role-ARN conftest rules named in 08-iac.md 'Deploy roles and OIDC' are not in this
  directory; they weren't in this PR's scope.
- `stateful.rego`'s "replace" detection is based on `resource_changes[].change.actions`
  containing `"delete"`. It does not attempt to detect a variable reference
  inside a `lifecycle` block (`prevent_destroy`), since Terraform's plan
  JSON `configuration` representation does not expose `lifecycle` blocks as
  of 1.12.x -- that check would need a different mechanism than conftest.
- `tags.rego` denies an aws provider whose `default_tags.tags` arrive with
  only `references`. Terraform 1.16.5 plans a literal map that way too, so a
  compliant root fails. The fix belongs on the `reese/iac-v0.3` branch.
- `student_pii_destinations.rego` does not read an `aws_s3_bucket_policy`
  whose `policy` is unknown at plan time, such as one built from a new
  bucket's ARN. Such policies are common, so the rule does not fail closed on
  them.
- `redact_plan.py` masks values a provider marks sensitive. A masked ECS
  `container_definitions` or Lambda `environment` hides the log-driver and
  OpenTelemetry checks.
- OPA drops a `telemetry-layers.yml` row whose `match` is not valid RE2
  without an error. Only the conftest-backed case in
  `scripts/iac/test_telemetry_layers.py` catches it.
- `check_classification_downgrade.py` reads map-shaped `tags` and `tags_all`.
  It misses an `awscc` resource's list of key and value pairs, a tag value
  masked as sensitive, and a `removed` block with `destroy = false`.
- On-prem roots have no downgrade check.
- The `logs:Unmask` grant check in `unmask.rego` skips a policy document
  unknown at plan time, such as one whose Resource references a new ARN. It
  also skips `aws_ssoadmin_permission_set_inline_policy` and resource-based
  policies.
- Attaching an AWS-managed policy that grants `logs:Unmask` (for example
  CloudWatchLogsFullAccess) to any role but the break-glass role is not caught.
- The break-glass trust check accepts the root of any account, and any
  12-digit account id in the `aws:PrincipalArn` pattern. The plan carries no
  trusted account anchor, so the rule cannot tell this account from another.
- The `aws:PrincipalArn` pattern ends in `AWSReservedSSO_<name>_*`, so it also
  matches a permission set named `<name>_<anything>`. Only an Identity Center
  administrator can create one, and that administrator can already grant
  any access.
- `account_controls.rego` compares identifier names only, so a custom
  identifier with a weakened regex passes. A pure delete of the account
  policy in the account-baseline root passes the plan, and no check reads
  the live account afterwards.
- An account-baseline root that never declares the account data protection
  policy passes the plan, because `account_controls.rego` fires only on a
  write to that policy.
- `psd:root = account-baseline` is self-asserted. A plan that carries the
  tag on some resources only is denied, and a resource whose `tags_all`,
  `psd:root` or `psd:data-classification` is not known at plan time counts
  against the tag. A student-pii root cannot
  become the baseline root by tagging: a resource tagged
  `psd:data-classification = student-pii` counts against the tag, so the
  app-root rules still apply and the plan is denied. A root that is not
  tagged student-pii and tags every resource, through its `default_tags`,
  gets the baseline rules. Those only add checks: they still require every
  identifier and confine Unmask to the break-glass role.
- Account policy types other than data protection and subscription filter,
  such as TRANSFORMER_POLICY, are not checked.
