# bun: the standard for JavaScript and TypeScript

Every PSD JavaScript and TypeScript repo uses [bun](https://bun.sh) as its package
manager and test runner. Not npm, not pnpm, not yarn.

Why one tool: when every repo works the same way, CI, Dependabot, coding agents, and
the person helping you debug all behave predictably. And bun specifically is fast,
runs TypeScript directly, and replaces npm, npx, and jest with one tool.

This standard covers the **package manager**, not your production runtime — apps
that deploy on Node or on a cloud platform keep doing so.

## Daily commands

| You used to run | Now run |
|---|---|
| `npm install` | `bun install` |
| `npm install <pkg>` | `bun add <pkg>` |
| `npm run <script>` | `bun run <script>` |
| `npx <tool>` | `bunx <tool>` |
| `npm test` | `bun test`, or `bun run test` if the repo defines a test script |

To install bun, run `curl -fsSL https://bun.sh/install | bash` on macOS and Linux,
or `powershell -c "irm bun.sh/install.ps1 | iex"` on Windows.

## Convert an existing repo

1. On a branch with a clean working tree, generate the bun lockfile:

   ```
   bun install
   ```

   This command reads `package.json` and writes `bun.lock`.
2. Delete the old lockfile: `package-lock.json` (npm), `pnpm-lock.yaml` (pnpm), or
   `yarn.lock` (yarn). Keep `package.json`.
3. Update anything that runs `npm ci` or `npm install` — CI configs, Dockerfiles,
   deploy scripts, the README — to run `bun install` instead.
4. If `.github/dependabot.yml` has `package-ecosystem: "npm"`, change that value to
   `"bun"`.
5. Before you open the PR, verify the conversion: run
   `bun install --frozen-lockfile`, then run the repo's tests and build.
6. Open a PR. In the description, state whether any dependency versions changed.
   Converting from npm usually changes none — say so explicitly.

One caution: packages that run install scripts, such as the native modules `sharp`
and `better-sqlite3`. bun blocks install scripts unless the package is listed in
`trustedDependencies` in `package.json`. If a package behaves oddly after install,
check `trustedDependencies` first.

## Check for an existing conversion PR

Many repos received a conversion PR from the standards rollout, labeled
`runtime-standard-wave`. If your repo has one open, review and merge that PR instead
of starting over.
