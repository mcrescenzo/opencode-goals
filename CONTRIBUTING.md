# Contributing

Issues and pull requests are welcome at:

<https://github.com/mcrescenzo/opencode-goals>

## Development setup

Use Node.js `>=20.11.0`. Install the one declared runtime dependency
(`@opencode-ai/plugin`) from the repository root:

```bash
bun install
# or: npm install
```

Run the local test suite:

```bash
node --test tests/*.test.mjs
```

This is also wired as the package's `test` script, so `bun run test` (or
`npm test`) runs the same command.

`tests/goals-plugin.test.mjs` is the helper-heavy regression file: it imports
the pure helpers directly from `goals-core.js` by name, so export an internal
helper from there when adding focused regression coverage.
`tests/command-registration.test.mjs` covers command registration and
package-metadata assertions; see the subsections below for the `pack-smoke`
and `runtime-smoke` gates.

### Packed-tarball release smoke

`tests/pack-smoke.test.mjs` is a no-token gate that proves the **published
artifact** is self-contained. It runs `npm pack` into a temp dir outside the
repo, extracts the tarball, dynamically imports the extracted entry, and asserts
that the `/goal` command and both hidden agents still register from the packed
tree — catching a `files` whitelist gap, a broken export, or a parent-config
assumption before release. It runs automatically as part of `npm test` (no
network, no model calls, no credentials).

The exact local command is:

```bash
node --test tests/pack-smoke.test.mjs   # or: npm test
```

### Zero-token runtime registration smoke

`tests/runtime-smoke.test.mjs` is a deterministic plugin-runtime harness for
startup registration. It constructs the real `GoalPlugin` in a temp workspace,
runs the `config` hook without relying on global model/provider configuration,
and asserts that:

- bundled `/goal` command registration succeeds;
- the hidden `goal-evaluator` denies all tools;
- the hidden `goal-researcher` is read-only with secret-path denies; and
- `/goal status` and `/goal help` command hooks return non-generating output
  without calling any client session/model prompt APIs.

Because the fake client throws on `session.prompt`, `session.promptAsync`,
`session.create`, `session.messages`, and `session.diff`, a passing run is
observable evidence that this smoke used zero model calls/tokens and cleaned up
its temp runtime state.

Run it directly with:

```bash
node --test tests/runtime-smoke.test.mjs   # or: npm test
```

### Opt-in host-contract smoke

`tests/host-contract-smoke.test.mjs` is skipped by default. When explicitly
enabled, it starts `opencode serve --pure` in a temp workspace using the normal
local opencode config, creates a real opencode session client with the local
SDK, and drives the hidden-session lifecycle through this package's session
helpers: parent create, hidden child create, child prompt, child abort, child
delete, and `hiddenSessionPrompt` cleanup. The prompt uses `noReply: true`, so
it is intended to exercise host request handling without model generation; if a
host still returns a provider/model runtime error for the prompt, the smoke keeps
checking request routing and cleanup rather than treating that as a path-shape
failure.

Run it only as a manual host-contract check:

```bash
OPENCODE_GOALS_HOST_SMOKE=1 node --test tests/host-contract-smoke.test.mjs
```

Optional knobs:

```bash
OPENCODE_GOALS_HOST_SMOKE_CLI=/path/to/opencode
OPENCODE_GOALS_HOST_SMOKE_TIMEOUT_MS=15000
OPENCODE_GOALS_HOST_SMOKE_CONFIG_CONTENT='{"model":"provider/model"}'
```

For a stronger manual release check, install the packed tarball into a throwaway
external project and confirm it resolves by name (this follows the Bun lockfile
install policy and does **not** publish):

```bash
npm pack --pack-destination /tmp/goals-rel
mkdir /tmp/goals-rel/probe && cd /tmp/goals-rel/probe
bun init -y
bun add /tmp/goals-rel/mcrescenzo-opencode-goals-*.tgz
node -e "import('@mcrescenzo/opencode-goals').then(m => console.log(typeof m.GoalPlugin))"
cd - && rm -rf /tmp/goals-rel
```

Before opening a pull request, also run the syntax and package checks used for release validation:

```bash
node --check goals.js && node --check goals-core.js && node --check goal-state.js && node --check diagnostics.js && node --check secret-redaction.js && node --check unicode-text.js
npm pack --dry-run --json
```

## Pull request expectations

- Avoid adding new runtime dependencies without maintainer review.
- Keep changes focused and avoid unrelated refactors.
- Add or update tests for behavior changes, especially around opencode SDK message/event shapes.
- Update README, SECURITY.md, CHANGELOG.md, or command docs when public behavior changes.
- Do not commit local runtime state such as `.opencode/`, `node_modules/`, logs, or generated tarballs (see `.gitignore` for the full list).
