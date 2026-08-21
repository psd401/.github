# The bots in your repo

Four kinds of automation touch PSD401 repos. This page covers what each one does,
what it's allowed to do, and what you're expected to do when it shows up.

## Dependabot: dependency updates

**What it does:** files PRs that bump your dependencies, weekly, grouped so you get
a few PRs instead of twenty.

**What you do:** treat them like any PR — CI must be green, then merge.

- Patch and minor updates with green CI are usually a quick merge.
- The config deliberately holds back major versions. When you want a major upgrade,
  do it in your own PR, where you can handle the breaking changes.
- Dependabot also files **security updates** when a dependency has a known
  vulnerability. Prioritize those.

## claude-review: the AI PR reviewer

**What it does:** comments on every human-opened PR with findings grouped by
severity. It's advisory only — a human always makes the merge decision. For more
information, see [Fix a failing PR check](ci-checks.md).

## OpenWiki: self-maintaining docs

**What it does:** some repos have an `openwiki/` folder of generated documentation.
A scheduled workflow keeps the folder in sync with the code: it opens a docs PR and
merges the PR itself, as the `psd-automation` app.

**What you do:** nothing. Don't hand-edit `openwiki/` files — the next run
overwrites your edits. If the generated docs are wrong, the fix belongs in the code
or its comments, not in the wiki output.

## The janitors: weekly org maintenance

**What they do:** two scheduled agents sweep the whole organization and report to
Technology Services:

- **Org janitor** (Mondays): licenses present, CI adopted, standards drift — such as
  a stray `package-lock.json` in a bun repo — and stale repos.
- **Security digest** (Tuesdays): open alerts, unpinned actions, and config drift.

**What you do:** usually nothing — they file reports, not changes. If a janitor
finding concerns your repo, Technology Services brings it to you as an issue or a
PR. The janitors never merge anything.

## Ground rules for all automation

- Every bot action is auditable — a PR, an issue, or a logged run. No silent
  changes.
- Bots follow the same rules you do: CI gates, PR flow, and branch protections.
- If a bot is doing something weird in your repo, report it to Technology Services.
  "The bot is wrong" is a bug report we want.
