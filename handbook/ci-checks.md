# Fix a failing PR check

Click **Details** next to the failing check. The log tells you which step failed.
Then find that check in the following sections.

## psd-ci: build, lint, and tests

This check is the main gate. It detects your project type from the lockfile and runs
install, lint, typecheck, tests, and build with the standard toolchain.

Common failures and their fixes:

| The log says | It means | Fix |
|---|---|---|
| Test failures | A test broke | Run the suite locally (`bun test` or `uv run pytest`), fix the test or the code, and push |
| No tests found, and the job fails | The repo has no tests | Add at least one real test. Failing on "no tests" is deliberate — if you think your repo genuinely can't have tests, see the [FAQ](faq.md) |
| Frozen lockfile error | `package.json` or `pyproject.toml` changed but the lockfile didn't | Run `bun install` or `uv lock` locally and commit the updated lockfile |
| Lint or typecheck errors | Style or type problems | Run the same command locally (it's printed in the log), fix the errors, and push |
| Runtime standard warning | The repo uses npm, pnpm, yarn, or pip instead of bun or uv | Not blocking yet, but convert before the warning becomes a failure: [bun](bun.md) or [uv](uv.md) |

Reproduce locally first. The log prints every command it ran, and running the same
command on your machine is almost always faster than pushing guesses.

## claude-review: the AI reviewer

An AI reviewer comments on every PR shortly after you open it. It flags issues by
severity. Fix **Critical** and **Important** findings, or explicitly rebut them in a
comment. Minor notes are your call.

- The review is advisory triage. It can't approve or block your PR by itself.
- The reviewer is sometimes wrong. If you disagree, say why in a reply — a human
  reviewer sees both sides. Don't silently ignore a Critical finding.
- It doesn't review Dependabot PRs, because there's no point reviewing a version
  bump.

## license-check

The repo must carry the MIT `LICENSE` file. If this check fails, someone removed or
renamed `LICENSE` — restore it. If you believe the repo needs a different license,
that's a Technology Services decision. Ask, don't swap it.

## security-scan

This check scans workflows and code for security problems: leaked secrets, risky
GitHub Actions patterns, and vulnerable dependency changes.

- **Secret detected**: remove the secret from the code, then rotate the credential —
  it's in git history now. Tell Technology Services. This is a no-blame process, and
  fast rotation is what matters.
- **Dependency review failure**: the PR adds a dependency with a known
  vulnerability. Use a patched version.
- **Workflow (zizmor) finding**: the log links to an explanation of the exact
  pattern and its fix.

## A human approval is missing

Production-tier repos require one human approval, and you can't approve your own
PR. Request a review from the repo's code owners — GitHub suggests them
automatically.

## Still stuck?

Open an issue on the repo and tag the owner, or contact Technology Services. Never
merge around a failing check — if the check is wrong, we fix the check.
