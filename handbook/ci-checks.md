# My PR check failed — what now?

Click **Details** next to the red ❌. The log tells you which step failed. Find that
check below.

## `psd-ci` — build, lint, and tests

This is the main gate. It detects your project type from the lockfile and runs
install → lint → typecheck → tests → build with the standard toolchain.

**Common failures and fixes:**

| Log says | It means | Fix |
|---|---|---|
| Test failures | A test broke | Run the suite locally (`bun test` or `uv run pytest`), fix, push |
| `No tests found` and the job fails | The repo has no tests | Add at least one real test. "No tests" failing is deliberate — see [FAQ](faq.md) if you think your repo genuinely can't have tests |
| Frozen lockfile error | `package.json`/`pyproject.toml` changed but the lockfile didn't | Run `bun install` or `uv lock` locally and commit the updated lockfile |
| Lint or typecheck errors | Style/type problems | Run the same command locally (it's printed in the log), fix, push |
| Runtime standard warning | Repo uses npm/pnpm/yarn/pip instead of bun/uv | Not blocking yet — but convert soon: [bun](bun.md) / [uv](uv.md) |

**Reproduce locally first.** The log prints every command it ran. Running the same
command on your machine is almost always faster than pushing guesses.

## `claude-review` — the AI reviewer

An AI reviewer comments on every PR shortly after you open it. It flags issues by
severity — treat **Critical** and **Important** findings as things to fix or
explicitly rebut in a comment; **minor** notes are your call.

- It's **advisory triage**. It cannot approve or block your PR by itself.
- It's sometimes wrong. If you disagree, say why in a reply — a human reviewer will
  see both sides. Don't silently ignore a Critical finding.
- It doesn't review Dependabot PRs (no point reviewing a version bump).

## `license-check`

The repo must carry the MIT LICENSE file. If this fails, someone removed or renamed
`LICENSE` — restore it. If you believe this repo needs a different license, that's a
Technology Services decision — ask, don't swap it.

## `security-scan`

Scans workflows and code for security problems: leaked secrets, risky GitHub Actions
patterns, and vulnerable dependency changes.

- **Secret detected**: remove it from the code, then **rotate the credential** — it's
  in git history now. Tell Technology Services; this is a no-blame process, and fast
  rotation is what matters.
- **Dependency review failure**: the PR adds a dependency with a known
  vulnerability. Use a patched version.
- **Workflow (zizmor) finding**: the log links an explanation of the exact pattern
  and its fix.

## A human approval is missing

Production-tier repos require one human approval, and it can't be you approving your
own PR. Request a review from the repo's code owners (GitHub suggests them
automatically).

## Still stuck?

Open an issue on the repo and tag the owner, or contact Technology Services. Never
merge around a failing check — if the check is wrong, we fix the check.
