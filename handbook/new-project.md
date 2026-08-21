# Starting a new project

**Don't start from an empty repo.** Start from a template — it carries the CI,
review workflow, license, Dependabot config, and agent instructions already wired up.

## 1. Pick a template

| Building… | Template |
|---|---|
| A web app (Next.js) | [template-nextjs-app](https://github.com/psd401/template-nextjs-app) |
| An MCP server | [template-mcp-server](https://github.com/psd401/template-mcp-server) |
| AWS infrastructure (CDK) | [template-cdk-app](https://github.com/psd401/template-cdk-app) |
| A Python CLI/tool | [template-python-tool](https://github.com/psd401/template-python-tool) |
| A Python web app | [template-python-webapp](https://github.com/psd401/template-python-webapp) |
| A Swift/iOS app | [template-swift-app](https://github.com/psd401/template-swift-app) |

On the template's page, click **Use this template → Create a new repository**, and
create it under the **PSD401** organization.

## 2. Choose visibility

**Public** is the default. Choose private only if the repo will contain student data
(FERPA) or sensitive infrastructure detail. If you're unsure, ask Technology
Services before creating it — moving from private to public later is easy; the
reverse is not really possible (public history stays out there).

## 3. First commits

- Update the README: what it is, who owns it, how to run it.
- Update `CLAUDE.md` / `AGENTS.md` with anything project-specific — both humans and
  coding agents read it before touching the repo.
- Keep the LICENSE file (MIT) — district code ships MIT unless Technology Services
  says otherwise.

## 4. What happens automatically

- CI runs on your first PR. See [CI checks](ci-checks.md) for what each check means.
- Dependabot starts filing weekly dependency-update PRs. See [The bots](bots.md).
- Technology Services assigns the repo a **tier** (production / internal /
  experiment) that controls how strict the merge rules are. New experiments start
  loose; tell Tech Services when something graduates to real use.

## If a template doesn't fit

Create the repo, then copy the `psd-ci` workflow in from the org's
**Actions → New workflow** page (the PSD templates are listed at the top). If you're
building something no template covers well, tell Technology Services — that's a
signal we need a new template.
