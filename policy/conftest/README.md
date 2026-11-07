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
  --all-namespaces
```

(`--policy policy/conftest/gcp` for a GCP-platform repo. `exceptions.yml` is
the consuming repo's own file at its root, schema in
[schemas/iac/exceptions.schema.json](../../schemas/iac/exceptions.schema.json); see
standards 08-iac.md 'Exceptions file'.)

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
