# PSD Developer Handbook

Plain-language guides for anyone writing code in the PSD401 organization — staff,
students, and outside contributors. Each page answers one question you'll actually
hit. Two minutes each.

| You want to… | Read |
|---|---|
| Understand what changed and why | Below, on this page |
| Start a new project | [New project](new-project.md) |
| Fix a red ❌ on your pull request | [CI checks](ci-checks.md) |
| Switch a JS/TS project to bun | [bun](bun.md) |
| Switch a Python project to uv | [uv](uv.md) |
| Know what the bots are doing in your repo | [The bots](bots.md) |
| Ask for an exemption, or something else | [FAQ](faq.md) |

## What changed, in one page

In August 2026 the district put shared engineering standards in place across every
PSD401 repository. The short version:

- **All district code is MIT-licensed and open by default.** Repos stay private only
  where student data or infrastructure detail requires it.
- **Every active repo runs the same CI.** Tests, lint, and build run automatically on
  each pull request. If tests exist, they must pass. If no tests exist, CI fails —
  that's deliberate.
- **AI reviews every pull request; a human approves it.** An AI reviewer comments on
  your PR within minutes. It's triage, not judgment — it never approves or blocks on
  its own, and production repos always need a human approval.
- **One toolchain per language.** [bun](bun.md) for JavaScript/TypeScript,
  [uv](uv.md) for Python. Today CI warns if a repo uses something else; that warning
  becomes a failure once the org finishes converting.
- **Pull requests, not direct pushes.** Changes to important repos go through a PR.
  This applies to everyone, including the bots and the CIO.

Why: most PSD code is now written with AI coding agents. Agents are fast and
inconsistent, so the guardrails moved out of people's heads and into the platform —
deterministic checks that pass or fail the same way for a human, an agent, or a bot.
Nothing here is aspirational; if it's a standard, a machine enforces it.

## Where the deep details live

- [CONTRIBUTING](../CONTRIBUTING.md) — the seven rules for every PR
- The internal `psd-dev-standards` repo — full standards, research, and decision
  history (district staff can request access from Technology Services)

*Something in this handbook wrong or confusing? Open an issue on this repo — that's
exactly what it's for.*
