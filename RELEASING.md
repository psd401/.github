# Releasing the reusable workflow library

Callers pin every reusable to a full commit SHA with the release in a comment:

```yaml
uses: PSD401/.github/.github/workflows/reusable-psd-ci.yml@<40-char sha> # v1.2.0
```

Each caller's Dependabot (`package-ecosystem: github-actions`) compares that
comment against this repo's `vX.Y.Z` tags and opens a PR moving both the SHA and
the comment to the newest release. A change merged to `main` reaches no caller
until it is released.

## Cutting a release

1. Merge the change to `main` through a PR.
2. **Actions → Release → Run workflow** on `main`, with `version` set to the
   next version. Leave `ref` as `main` unless releasing an older commit that is
   already on `main`. The workflow refuses a malformed version, an existing tag,
   a version not higher than the latest, and a commit not on `main`. It creates
   the tag and a GitHub release with generated notes.
3. Open a PR updating the pins in `workflow-templates/` to the new SHA and
   version (Dependabot doesn't scan that folder).

## Which number to bump

| Bump | When | Examples |
|------|------|----------|
| MAJOR | A caller has to change its file | New required input or secret, removed or renamed input, renamed job (changes the required-check name), caller must grant new `permissions:` |
| MINOR | New capability, callers unaffected | New optional input, new reusable workflow |
| PATCH | Behavior fix, callers unaffected | Bug fix, SHA bump of an action used inside a reusable, OpenWiki pin bump |

Dependabot proposes majors too; the caller's reviewer reads the release notes
before merging one.

## What a pinned caller gets

Everything a reusable loads from this repo comes from the same commit as the
reusable itself (`job.workflow_sha`), not from `main`:

- `reusable-openwiki.yml` installs openwiki from `tools/openwiki/package-lock.json`
  with `npm ci`.
- `reusable-publish-plugin.yml` runs `scripts/` and installs Claude Code from
  `tools/claude-code/package-lock.json` at that commit (`tooling_ref` overrides
  it only for testing).
- `reusable-security-scan.yml` installs zizmor with `pip --require-hashes` and
  checks gitleaks against its release checksum.

## Bumping a locked tool

1. Change the version in `tools/<tool>/package.json`.
2. In that folder, run `npm install --package-lock-only --before=<date 7+ days ago>`.
   The date keeps a dependency published minutes earlier out of the lockfile.
3. Commit both files in one PR, then cut a release once it merges.
