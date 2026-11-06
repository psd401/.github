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

Standards source of truth: the internal `psd-dev-standards` repo.
