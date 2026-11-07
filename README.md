# PSD401/.github

Org-wide defaults and the **reusable workflow library** for Peninsula School District.

- Community health files (SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, PR/issue templates) apply to every repo that doesn't override them.
- `.github/workflows/reusable-*.yml` — the org-standard CI, Claude review, OpenWiki, license, and security jobs. **Version pins (like OpenWiki's) live here once, org-wide.**
- `workflow-templates/` — starter workflows offered on every repo's Actions tab.
- **Releases.** Callers pin each reusable to a release commit SHA (`@<sha> # vX.Y.Z`); their Dependabot opens bump PRs as new `vX.Y.Z` tags appear. How to cut one: [RELEASING.md](RELEASING.md).

## IaC: `reusable-env-file-check.yml`

Validates a district's private `<district-id>.env.yml` against [`schemas/iac/environment-file.schema.json`](schemas/iac/environment-file.schema.json) before any Terraform or Packer job reads it. The job prints schema error paths only, never a value from the file. [`schemas/iac/example.env.yml`](schemas/iac/example.env.yml) is a placeholder instance.

```yaml
jobs:
  env-file-check:
    uses: PSD401/.github/.github/workflows/reusable-env-file-check.yml@<40-char sha> # vX.Y.Z
    secrets:
      PSD_ENV_FILE_CONTENTS: ${{ secrets.PSD_ENV_FILE_CONTENTS }} # base64 of the env file
```

- Pin a release SHA, like every reusable. The schema and the hash-locked validator deps (`tools/iac/requirements.txt`) load from that same commit (`job.workflow_sha`), so a pinned caller never runs `main`'s schema.
- Pass the secret by name; don't use `secrets: inherit`. The job needs only `contents: read`.
- Run the tests locally: `uv run --no-project --with-requirements tools/iac/requirements-test.txt -- pytest scripts/iac`.

## IaC: `reusable-iac-checks.yml`

The CI and apply contract for Terraform repos on AWS or GCP: env-file check, redaction check, fmt/validate/tflint, plan (redacted, sealed to `plan_recipient` with age), checkov, conftest against [`policy/conftest/`](policy/conftest/), infracost, and an environment-gated apply. The file header has the full caller block for a plan-only call and an applying call.

```yaml
jobs:
  dev:
    uses: PSD401/.github/.github/workflows/reusable-iac-checks.yml@<40-char sha> # vX.Y.Z
    environment: dev
    with:
      working_directory: envs/dev
      platform: aws
      tier: b-internal
    secrets:
      PSD_ENV_FILE_CONTENTS: ${{ secrets.PSD_ENV_FILE_CONTENTS }}
      INFRACOST_API_KEY: ${{ secrets.INFRACOST_API_KEY }}
```

- Inputs: `working_directory` (required), `environment`, `platform` (`aws`/`gcp`), `tier`, `aws_region`, `plan_role_arn`, `apply_role_arn`, `apply`, `plan_recipient`, `account_alias`, `tooling_ref`. Secrets: `PSD_ENV_FILE_CONTENTS` (required), `INFRACOST_API_KEY`, `PSD_PLAN_KEY`.
- `policy/`, `scripts/iac/`, `schemas/iac/` and `tools/iac/` load from the pinned commit. `tooling_ref` overrides that ref; leave it empty except to test a change to those paths.
- Python helpers install from `tools/iac/requirements.txt` with `pip --require-hashes` (yamllint, in the on-prem reusable, from `tools/iac/requirements-yamllint.txt`); age and conftest install through `scripts/iac/install_*.sh`, which check a pinned SHA-256.

## IaC: `reusable-onprem-checks.yml`

The CI contract for on-prem repos (Compose/systemd apps and Proxmox VMs): env-file check, redaction check, yamllint, Packer and Terraform validate, a Proxmox plan, conftest on Compose and Terraform, and the exceptions cross-check.

```yaml
jobs:
  onprem-checks:
    uses: PSD401/.github/.github/workflows/reusable-onprem-checks.yml@<40-char sha> # vX.Y.Z
    with:
      working_directory: .
      tier: b-internal
      self_hosted_runner: false
    secrets:
      PSD_ENV_FILE_CONTENTS: ${{ secrets.PSD_ENV_FILE_CONTENTS }}
      PROXMOX_API_TOKEN: ${{ secrets.PROXMOX_API_TOKEN }}
```

- Inputs: `working_directory` (required), `tier`, `self_hosted_runner`, `tooling_ref` (same meaning as above). Secrets: `PSD_ENV_FILE_CONTENTS` and `PROXMOX_API_TOKEN` (both required).
- `packer-validate` and `plan` run only with `self_hosted_runner: true`, on a `[self-hosted, proxmox]` runner. That runner needs `python3` with the `venv` module; the plan job builds a hash-locked venv from it.
- The policy tests run in CI (`iac-tests.yml`): `conftest verify --policy policy/conftest/<platform> --data policy/conftest/fixtures/<platform>` for `aws`, `gcp` and `onprem`.

Standards source of truth: the internal `psd-dev-standards` repo.
