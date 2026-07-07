# goals — the `/goal` plugin for opencode

An opencode plugin that adds a single, persistent **`/goal`** for a session and
keeps the assistant auto-continuing until a hidden evaluator agent decides the
goal is actually achieved — not merely until the assistant claims it is.

## What it does

`/goal <objective>` sets one session goal. After each assistant turn the plugin
relays bounded, sanitized evidence (a recent transcript excerpt, tool call/result
summaries, the session diff, the goal text, and any assistant-claimed evidence)
to a hidden **`goal-evaluator`** agent, which returns the final structured
verdict. For file/test/docs/review-oriented goals a hidden read-only
**`goal-researcher`** agent may gather additional evidence first. Until the
evaluator marks the goal met (or the goal is blocked, paused, or its budget is
exhausted), the plugin sends an auto-continue prompt so work proceeds without a
human re-prompting each turn.

Key behaviors:

- **Evaluator has final say.** Assistant markers are signals, not authority. The
  assistant may emit `[goal:evidence] ...` immediately before a terminal
  `[goal:complete]`, and `[goal:blocked]` (preceded by a concrete blocker) to
  pause — but only the hidden evaluator marks a goal achieved.
- **Two hidden agents, locked down.** `goal-evaluator` runs with all tools
  denied; `goal-researcher` is deny-by-default with only targeted `read` and
  `grep` allowed under secret-path deny rules (`.env`, `*.pem`, `*.key`,
  credentials, secrets, tokens). Broad `glob`, `list`, and `lsp` enumeration is
  denied. Both inherit the session's configured model.
- **Human-first pausing.** A real user message after the last auto-continuation
  pauses before any hidden agent or further continuation, so the latest human
  instruction wins. Permission/question prompts block automation while waiting;
  a rejection pauses the goal.
- **Runaway backstops.** Beyond the per-goal turn budget there are lifetime
  ceilings (a ~3-hour wall-clock cap and a hidden-call budget) and stall
  heuristics that pause repeated low-progress, no-tool-call, or repeated-diff
  loops with no criteria progress. These are not reset by `/goal resume`.
- **Verification and observe modes.** A `--verify` directive tells the build
  agent which command to run under its normal permissions (the plugin never
  executes it), and `--observe` lets the evaluator report not-met verdicts
  without auto-continuing.
- **Polite progress toasts.** The active session goal emits compact lifecycle
  toasts plus a best-effort heartbeat while active, including the objective,
  turn usage, latest evaluator reason, verification failure, or error summary.
- **Persistence + recovery.** Goal state is written per workspace and active
  goals recover as *paused* after an opencode restart (see Persistence below).

The plugin self-registers the `/goal` command from its bundled `commands/goal.md`; no separate command file is required.

> Privacy: hidden evaluator/researcher calls send transcript excerpts, bounded
> tool summaries, diffs, goal text, and research summaries to the configured
> model/provider. Secret-path protections redact file/diff/research content for
> sensitive paths, and transcript text receives best-effort inline credential
> pattern redaction before hidden-agent relay, including common key assignments,
> provider token prefixes, bearer/basic auth, cookies, URL credentials, PEM keys,
> AWS access keys, JWT-shaped strings, and session/csrf-style token prefixes.
> This is not a comprehensive secrecy boundary: arbitrary opaque secrets may not
> match these patterns, do not paste secrets into chat, and nested `.gitignore`
> files are not a secrecy boundary for transcript evidence.

## Commands

- `/goal <objective>` — start or replace the session goal.
- `/goal status` — objective, criteria, constraints, turn usage, evaluator
  reason, evidence, blocker, and recent history.
- `/goal help`, `/goal --help`, `/goal -h` — usage summary for the command
  surface and completion marker.
- `/goal history` — lifecycle events for the current session goal.
- `/goal pause`, `/goal resume`, `/goal clear` — control automation.
- `/goal observe`, `/goal observe on`, `/goal observe off` — toggle observe
  mode, where hidden evaluation/research still runs but not-met verdicts pause
  instead of auto-continuing.
- `/goal continue` or `/goal step` — send one explicit continuation, useful
  after an observe-mode verdict pause.
- `/goal edit <new objective>` — revise the objective while preserving the turn
  limit and history; omitted success, constraints, and verify flags are cleared.
- Clear aliases: `clear`, `stop`, `off`, `reset`, `none`, `cancel`.

## Install and registration

Install the published package with your package manager of choice:

```bash
bun add @mcrescenzo/opencode-goals
# or
npm install @mcrescenzo/opencode-goals
```

The plugin declares one runtime dependency, `@opencode-ai/plugin` — the opencode
plugin-host contract this package is written against — and installs no other
packages of its own; the plugin source imports only Node built-ins and receives
its opencode context (agents, commands, client, session events) from the host
at runtime.

Register the plugin in the `"plugin"` array of your opencode config
(`opencode.json`). There are two ways to load it:

**Published package** — use the package name directly (opencode resolves it like
any configured plugin):

```json
{
  "plugin": [
    "@mcrescenzo/opencode-goals"
  ]
}
```

**Source checkout** — clone this repository anywhere on disk, run `bun install`
(or `npm install`) once, and register the entry file by path (relative to your
config directory, or absolute):

```json
{
  "plugin": [
    "./path/to/opencode-goals/goals.js"
  ]
}
```

Restart opencode to activate the plugin. The source of truth is the entry in
`opencode.json`; `~/.config/opencode/plugins/` is only the runtime discovery
shell. After changing the plugin source or the bundled command docs, **restart
opencode** — already-running sessions keep the plugin, commands, and agents they
loaded at startup.

**If `/goal` is not available**, confirm the `opencode.json` `"plugin"` array
contains either the package name (`@mcrescenzo/opencode-goals`) or a valid,
readable path to `goals.js`, and that opencode was restarted after the edit.

## Hooks

`goals.js` wires exactly five hooks on the plugin factory it exports
(`GoalPlugin`):

| Hook | What it does here |
|---|---|
| `config` | Self-registers the `/goal` command from the bundled `commands/goal.md` and defines the two hidden agents, `goal-evaluator` (all tools denied) and `goal-researcher` (read-only, secret-path denies). |
| `"chat.message"` | Tracks the human-authored build turn's agent/model and, on a genuine human message during an active goal, marks the goal human-interrupted so auto-continuation yields to the user. |
| `"command.execute.before"` | Intercepts the `/goal` command (set, status, pause, resume, clear, etc.) before it reaches the model and replaces the turn's parts with the plugin's own output. |
| `event` | Fire-and-forget session-event listener: tracks permission/question ask-and-reply to block/unblock automation, pauses on rejections and session errors, and triggers hidden evaluation on session idle. |
| `"experimental.session.compacting"` | Injects a deduplicated goal-state context block into the compaction prompt so an active goal survives context compaction. |

## opencode compatibility

The plugin targets Node.js **`>=20.11.0`** and the current/latest opencode
session-client contract checked during release preparation (`opencode --version`
observed as `1.17.13`). Its source imports no `@opencode-ai/*` module directly;
`@opencode-ai/plugin` is declared only to pin the host contract version.

Session client calls prefer the v2 option-object shape `path: { sessionID }`.
Because local `@opencode-ai/sdk`/`@opencode-ai/plugin` `1.17.7` installs still
show an injected v1-style plugin client requiring `path: { id }`, the adapter
falls back to that observed v1 path shape only for request-shape incompatibility
errors. Message, tool-result, and diff parsing also retains compatibility with
observed v1 payloads such as assistant agent identity in `info.mode`, tool
input/output under `state`, and `FileDiff` records with `before`/`after`.

## Support and security

Use GitHub Issues for public bugs, support requests, and feature proposals:

<https://github.com/mcrescenzo/opencode-goals/issues>

Do **not** post secrets, credentials, private logs, exploit details, sensitive
vulnerability details, or private workspace data in public issues. See
`SECURITY.md` for the current reporting policy, `CONTRIBUTING.md` for pull
request expectations, and `CHANGELOG.md` for release notes.

## Running the tests

The suite uses Node's built-in `node:test` runner — no external test framework.
Run it from the plugin root:

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

## Configuration options

Most configuration is **per goal**, supplied as flags when setting a goal. Value
flags accept both `--flag value` and `--flag="multi word value"` forms; boolean
flags use bare or inline forms. Use `--` before objective text that contains
literal `--flag` tokens:

- `--max-turns <n>` — auto-continue turn budget. Default: **100**.
- `--success "criteria"` — explicit success criteria the evaluator must verify.
- `--constraints "constraints"` / `--non-goals "constraints"` — constraints and
  non-goals to honor.
- `--verify "command"` — frozen build-agent verification directive. The plugin
  does not execute this command; it injects the directive into goal context and
  the evaluator treats transcript-visible results as authoritative evidence.
- `--observe` — hidden evaluation/research still runs and is budgeted, but
  not-met verdicts pause with the verdict instead of sending auto-continuations.
  Use bare `--observe` to enable it, or inline boolean forms such as
  `--observe=off`; accepted boolean tokens are `true`/`false`, `on`/`off`,
  `yes`/`no`, and `1`/`0`.

Notable defaults and safety limits (constants in `goals-core.js`, not currently
user-configurable):

- Default auto-continue budget: 100 turns.
- Minimum delay between auto-continues: ~1s.
- Per-goal lifetime wall-clock cap: ~3 hours (a runaway backstop, **not** reset
  by `/goal resume`; a fresh `/goal` or `/goal edit` starts it over).
- Hidden-call budget scaled to the turn budget, plus stall heuristics that pause
  after repeated low-progress or no-tool-call continuation turns.

The hidden `goal-evaluator` and `goal-researcher` agents take their model from
the session's configured model (`cfg.model`) — no model ID is hard-coded.

## Persistence

Goal state is written per workspace:

```text
.opencode/goals/state.json
.opencode/goals/state.json.ledger.jsonl
.opencode/goals/cycles.jsonl
```

Active goals recover as **paused** after an opencode restart; run `/goal resume`
to continue with fresh turn and stall counters. State writes are refused when the
goals directory or state/ledger/cycle-ledger path is an existing symlink or escapes the
project directory. The cycle ledger stores bounded structured evaluator records
(verdict, criteria, diff fingerprint, verify evidence, and audit context) for
incremental criteria stability and stuck-loop detection. Keep `.opencode/goals/` out of git unless a project
intentionally wants local goal history committed.

## Development notes

See `AGENTS.md` in this directory for contributor invariants (SDK contract
direction, hidden-agent behavior, and testing expectations).
