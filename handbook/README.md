# PSD Developer Handbook

Plain-language guides for anyone writing code in the PSD401 organization — staff,
students, and outside contributors. Each page answers one question you'll actually
hit, in about two minutes.

| Task | Guide |
|---|---|
| Understand what changed and why | The following section |
| Start a new project | [Start a new project](new-project.md) |
| Fix a failing check on your pull request | [Fix a failing PR check](ci-checks.md) |
| Switch a JavaScript or TypeScript project to bun | [bun](bun.md) |
| Switch a Python project to uv | [uv](uv.md) |
| Understand what the bots are doing in your repo | [The bots](bots.md) |
| Ask for an exemption, or anything else | [FAQ](faq.md) |

## What changed, in one page

In August 2026, the district put shared engineering standards in place across every
PSD401 repository. The short version:

- **All district code is MIT-licensed and open by default.** Repos stay private only
  where student data or infrastructure detail requires it.
- **Every active repo runs the same CI.** Tests, lint, and build run automatically on
  each pull request. If tests exist, they must pass. If no tests exist, CI fails —
  that's deliberate.
- **AI reviews every pull request, and a human approves it.** An AI reviewer comments
  on your PR within minutes. It's triage, not judgment — it never approves or blocks
  on its own, and production repos always need a human approval.
- **One toolchain per language.** [bun](bun.md) for JavaScript and TypeScript,
  [uv](uv.md) for Python. CI warns if a repo uses something else. That warning
  becomes a failure after the org finishes converting.
- **Pull requests, not direct pushes.** Changes to important repos go through a PR.
  This rule applies to everyone, including the bots and the CIO.

Why: most PSD code is now written with AI coding agents. Agents are fast and
inconsistent, so the guardrails moved out of people's heads and into the platform —
deterministic checks that pass or fail the same way for a human, an agent, or a bot.
Nothing here is aspirational. If it's a standard, a machine enforces it.

## Where the deep details live

- [CONTRIBUTING](../CONTRIBUTING.md) — the seven rules for every PR
- The internal `psd-dev-standards` repo — full standards, research, and decision
  history. District staff can request access from Technology Services.

If something in this handbook is wrong or confusing, open an issue on this repo —
that's exactly what issues here are for.
