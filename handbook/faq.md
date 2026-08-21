# FAQ & exemptions

## How do I get an exemption from a standard?

Ask Technology Services, with the reason. Exemptions exist and are granted — but
they're **documented, never silent**. A repo that legitimately can't follow a
standard gets an explicit, visible opt-out (a config line with a comment saying
why), so the next person doesn't mistake it for drift.

Known legitimate exemptions:

- **Vendor forks**: a fork tracking an upstream project keeps the upstream's
  toolchain (npm, pip, whatever). Converting it would make every upstream merge a
  conflict. These repos set the runtime-standard check to `off` with a comment.
- **Repos that genuinely can't have tests**: rare — config-only or data-only repos
  mostly. The bar is "can't", not "don't yet".

## The AI reviewer is wrong about my code. Do I have to obey it?

No. Reply to the finding explaining why it's wrong, and the human reviewer decides.
What you can't do is silently ignore a Critical finding — engage or fix.

## Why does CI fail when there are no tests?

Because "no tests, green check" teaches everyone that green means nothing. A repo
with zero tests failing CI is the system telling the truth. Add one real test —
even a single test that exercises the main path is a meaningful start.

## Why can't I push straight to main?

On production and internal-tier repos, changes go through a PR so they get CI and
review. This applies to everyone — bots, agents, Technology Services, the CIO. If
you're doing rapid solo prototyping, that's what experiment-tier repos are for; ask
Tech Services to tier your repo accordingly.

## Why bun and uv instead of what I already know?

Mostly-AI-written code changes the math: agents work far better when every repo
behaves identically, and one lockfile format per language means CI and Dependabot
work everywhere without per-repo special cases. bun and uv are also simply fast,
which you'll feel every day. Your npm/pip knowledge transfers almost 1:1 — see the
command tables in [bun](bun.md) and [uv](uv.md).

## I found a security problem. Where do I report it?

Use the repo's **Security tab → Report a vulnerability** (private, doesn't create a
public issue), or contact Technology Services directly. If you accidentally
committed a secret: remove it, **rotate it**, and tell Tech Services — no blame,
speed matters.

## My question isn't here

Open an issue on this repo. If you had the question, someone else will too, and the
answer probably belongs in this handbook.
