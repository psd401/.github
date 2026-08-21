# The bots in your repo

Four kinds of automation touch PSD401 repos. Here's what each one does, what it's
allowed to do, and what you're expected to do when it shows up.

## Dependabot — dependency updates

**What it does:** files PRs bumping your dependencies, weekly, grouped so you get a
few PRs instead of twenty.

**What you do:** treat them like any PR — CI must be green, then merge.

- Patch and minor updates with green CI are usually a quick merge.
- **Major versions are held back on purpose** (the config ignores them). When you
  want a major upgrade, do it deliberately in your own PR where you can handle the
  breaking changes.
- It also files **security updates** when a dependency has a known vulnerability —
  prioritize those.

## claude-review — the AI PR reviewer

Comments on every human-opened PR with findings by severity. Advisory only; a
human always makes the merge decision. Details in [CI checks](ci-checks.md).

## OpenWiki — self-maintaining docs

Some repos have an `openwiki/` folder of generated documentation. A scheduled
workflow keeps it in sync with the code: it opens a docs PR and merges it itself
(as the `psd-automation` app).

**What you do:** nothing. Don't hand-edit `openwiki/` files — the next run will
overwrite your edits. If the generated docs are wrong, the fix is in the code or
its comments, not the wiki output.

## The janitors — weekly org maintenance

Two scheduled agents sweep the whole organization and report to Technology
Services:

- **Org janitor** (Mondays): licenses present, CI adopted, standards drift (like a
  stray `package-lock.json` in a bun repo), stale repos.
- **Security digest** (Tuesdays): open alerts, unpinned actions, config drift.

**What you do:** usually nothing — they file reports, not changes. If a janitor
finding concerns your repo, Technology Services will bring it to you as an issue
or PR. The janitors never merge anything.

## Ground rules for all automation

- Every bot action is auditable — a PR, an issue, or a logged run. No silent
  changes.
- Bots follow the same rules you do: CI gates, PR flow, branch protections.
- If a bot is doing something weird in your repo, report it to Technology
  Services. "The bot is wrong" is a bug report we want.
