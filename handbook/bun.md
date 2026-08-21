# bun — the standard for JavaScript and TypeScript

Every PSD JS/TS repo uses [bun](https://bun.sh) as its package manager and test
runner. Not npm, not pnpm, not yarn.

**Why one tool:** every repo working the same way means CI, Dependabot, coding
agents, and the person helping you debug all behave predictably. bun specifically:
it's fast, it runs TypeScript directly, and one tool replaces npm + npx + jest.

This standardizes the **package manager**, not your production runtime — apps that
deploy on Node or on a cloud platform keep doing so.

## Daily commands

| You used to run | Now run |
|---|---|
| `npm install` | `bun install` |
| `npm install <pkg>` | `bun add <pkg>` |
| `npm run <script>` | `bun run <script>` |
| `npx <tool>` | `bunx <tool>` |
| `npm test` | `bun test` (or `bun run test` if the repo defines a test script) |

Install bun: `curl -fsSL https://bun.sh/install | bash` (macOS/Linux) or
`powershell -c "irm bun.sh/install.ps1 | iex"` (Windows).

## Converting an existing repo

1. On a branch, with a clean working tree:

   ```
   bun install
   ```

   This reads `package.json` and writes `bun.lock`.
2. Delete the old lockfile: `package-lock.json` (npm), `pnpm-lock.yaml` (pnpm), or
   `yarn.lock` (yarn). Keep `package.json`.
3. Update anything that says `npm ci` or `npm install` — CI configs, Dockerfiles,
   deploy scripts, README — to `bun install`.
4. If `.github/dependabot.yml` has `package-ecosystem: "npm"`, change it to
   `"bun"`.
5. Verify before opening the PR: `bun install --frozen-lockfile`, then run the
   repo's tests and build.
6. Open a PR. In the description, state whether any dependency versions changed
   (converting from npm usually changes none — say so).

**Careful with:** packages that run install scripts (native modules like `sharp` or
`better-sqlite3`). bun blocks postinstall scripts unless the package is listed in
`trustedDependencies` in `package.json`. If something behaves oddly after install,
this is the first thing to check.

## Already converted for you?

Many repos received a conversion PR from the standards rollout (label
`runtime-standard-wave`). If your repo has one open, review and merge that instead
of starting over.
