# Start a new project

Don't start from an empty repo. Start from a template — it carries the CI,
review workflow, license, Dependabot config, and agent instructions already wired up.

## 1. Pick a template

| Project type | Template |
|---|---|
| Web app (Next.js) | [template-nextjs-app](https://github.com/psd401/template-nextjs-app) |
| MCP server | [template-mcp-server](https://github.com/psd401/template-mcp-server) |
| AWS infrastructure (CDK) | [template-cdk-app](https://github.com/psd401/template-cdk-app) |
| Python CLI or tool | [template-python-tool](https://github.com/psd401/template-python-tool) |
| Python web app | [template-python-webapp](https://github.com/psd401/template-python-webapp) |
| Swift or iOS app | [template-swift-app](https://github.com/psd401/template-swift-app) |

On the template's page, select **Use this template > Create a new repository**, and
create the repository under the **PSD401** organization.

## 2. Choose visibility

**Public** is the default. Choose private only if the repo will contain student data
(FERPA) or sensitive infrastructure detail. If you're unsure, ask Technology
Services before you create the repo. You can make a private repo public later, but
you can't truly take a public repo private again — the public history stays out
there.

## 3. Make your first commits

- Update the README: what the project is, who owns it, and how to run it.
- Update `CLAUDE.md` or `AGENTS.md` with anything project-specific — both humans and
  coding agents read these files before touching the repo.
- Keep the `LICENSE` file (MIT). District code ships MIT unless Technology Services
  says otherwise.

## 4. Know what happens automatically

- CI runs on your first PR. For more information about each check, see
  [Fix a failing PR check](ci-checks.md).
- Dependabot starts filing weekly dependency-update PRs. See [The bots](bots.md).
- Technology Services assigns the repo a **tier** — production, internal, or
  experiment — that controls how strict the merge rules are. New experiments start
  loose. Tell Technology Services when something graduates to real use.

## If a template doesn't fit

Create the repo, then add the `psd-ci` workflow from the org's
**Actions > New workflow** page — the PSD templates are listed at the top. If you're
building something no template covers well, tell Technology Services. That's a
signal we need a new template.
