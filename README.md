# PSD401/.github

Org-wide defaults and the **reusable workflow library** for Peninsula School District.

- Community health files (SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, PR/issue templates) apply to every repo that doesn't override them.
- `.github/workflows/reusable-*.yml` — the org-standard CI, Claude review, OpenWiki, license, and security jobs. **Version pins (like OpenWiki's) live here once, org-wide.**
- `reusable-deploy-ecs.yml` — build an image, push to ECR, register a task definition revision, run migrations as a one-off task, and roll an ECS Fargate service, through the caller's OIDC deploy role and GitHub environment protection. First used by psd-athletics.
- `workflow-templates/` — starter workflows offered on every repo's Actions tab.

Standards source of truth: the internal `psd-dev-standards` repo.
