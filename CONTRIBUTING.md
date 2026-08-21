# Contributing to PSD401 repositories

Contributions welcome — from staff, students, other districts, and the community.

*New here? The [PSD Developer Handbook](handbook/README.md) covers starting a project, fixing a failing CI check, and the standard toolchain in plain language.*

## The rules that matter

1. **Disclose AI assistance.** State the tool and extent in your PR description. AI-assisted PRs are welcome; undisclosed ones are not.
2. **One concern per PR.** Small and reviewable beats big and impressive.
3. **Self-review first.** Strip agent verbosity from the description; state the purpose in one sentence.
4. **Never weaken CI.** Removed or skipped tests, loosened lint rules, or disabled checks are automatic blockers unless explicitly justified.
5. **Bring evidence.** Test output, commands run, screenshots. "It works" is not evidence.
6. **You own every line you submit**, regardless of what wrote it.
7. External contributions should reference an open issue first — drive-by feature PRs to production repos will likely be closed with a pointer here.

## Practical notes

- District-authored repos are MIT-licensed; by contributing you agree your contribution is MIT too.
- CI must be green before review is requested. Production-tier repos require one human approval to merge.
- Repos carry a `CLAUDE.md`/`AGENTS.md` — agents and humans should both read it.
