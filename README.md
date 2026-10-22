# PSD401/.github

Org-wide defaults and the **reusable workflow library** for Peninsula School District.

- Community health files (SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, PR/issue templates) apply to every repo that doesn't override them.
- `.github/workflows/reusable-*.yml` — the org-standard CI, Claude review, OpenWiki, license, and security jobs. **Version pins (like OpenWiki's) live here once, org-wide.**
- `workflow-templates/` — starter workflows offered on every repo's Actions tab.
- **Releases.** Callers pin each reusable to a release commit SHA (`@<sha> # vX.Y.Z`); their Dependabot opens bump PRs as new `vX.Y.Z` tags appear. How to cut one: [RELEASING.md](RELEASING.md).

Standards source of truth: the internal `psd-dev-standards` repo.
