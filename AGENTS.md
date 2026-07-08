# Goals Plugin Notes

**Contract version:** `@opencode-ai/plugin@1.17.7` (declared range: `^1.17.7`)
**Verified against runtime:** opencode 1.17.13

- This directory is its own git repo; commit plugin code and tests here.
- The `/goal` command is self-registered by the plugin's `config` hook from the bundled `commands/goal.md`.
- The root `package.json` declares `@mcrescenzo/opencode-goals` and the `test` script; the tracked CI workflow runs Bun install, Node syntax checks, `npm test`, and `npm pack --dry-run --json`. There is no separate linter, formatter, or typecheck config in this plugin repo. Use plain Node for tests.
- Run the full local suite with `node --test tests/*.test.mjs` from this directory (also wired as `npm test`); focused regression files now include `tests/goals-plugin.test.mjs`, `tests/sdk-adapter.test.mjs`, `tests/diagnostics.test.mjs`, and `tests/parser-redaction.test.mjs`.
- Shared test factories live in `tests/helpers.mjs`; keep broad cross-domain helpers there rather than redefining them in individual test files.
- Tests import the pure helpers directly from `goals-core.js` by name (and the wired `GoalPlugin` from `goals.js`); add an export to `goals-core.js` when new test coverage needs an internal helper.
- `.opencode/`, `node_modules/`, logs, and other local dev/agent-tooling state are intentionally ignored by this repo (see `.gitignore`).
- Runtime `/goal` state is written per workspace under `.opencode/goals/state.json`, `.opencode/goals/state.json.ledger.jsonl`, and `.opencode/goals/cycles.jsonl`; do not treat those files as source fixtures unless a test creates them in a temp directory.
- The plugin defines two hidden agents in its `config` hook: `goal-evaluator` has all tools denied, and `goal-researcher` is read-only with secret-path deny rules.
- Hidden-agent behavior depends on opencode SDK message/event shapes; when fixing transcript, permission, diff, or tool-result bugs, add tests with the real shape being handled instead of only simplified mocks.
- SDK contract direction (re-verified 2026-07-02, goals-v2-migration): current public target checked by the controller was opencode CLI `1.17.13` and npm `@opencode-ai/{plugin,sdk}` `1.17.13`; local installed `@opencode-ai/{plugin,sdk}` track the `^1.17.7` range and include both v1 (`dist/gen/`) and v2 (`dist/v2/gen/`) contracts. Source imports no `@opencode-ai/*` module directly; `@opencode-ai/plugin` is declared as the sole `dependencies` entry to pin the host contract version. Session-client calls now go through `goals-core.js` helpers that prefer the v2 option-object path shape `path:{sessionID}` and fall back only on request-shape incompatibility to the observed injected v1 plugin-client shape `path:{id}`. Keep observed v1 payload defenses unless the runtime contract is proven otherwise: assistant agent identity in `info.mode`, `ToolStateCompleted` input/output under `state`, `FileDiff = {file,before,after,additions,deletions}` with no `patch`, and permission events `permission.updated`/`permission.replied`.
- After changing this plugin or the parent slash-command docs/config, restart opencode; running sessions keep already-loaded plugins, commands, agents, and instructions.

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
