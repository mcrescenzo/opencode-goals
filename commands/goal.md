---
description: Set, inspect, pause, resume, or clear a session goal that keeps opencode working until complete
---

Manage the active /goal for this session with arguments: `$ARGUMENTS`.

The goals plugin intercepts this command before it reaches the model. If you are reading this as a normal prompt, the plugin is not loaded — confirm the goals plugin entry (the package name `@mcrescenzo/opencode-goals` once published, or the path-based `./plugins/goals/goals.js` for dev) is in your opencode `plugin` config and restart opencode.

Privacy note: `/goal` can make hidden evaluator/researcher model calls using recent transcript excerpts, bounded/sanitized tool call or result summaries, session diffs, goal text, assistant-claimed evidence, and read-only research summaries. Secret-path protections apply to file/diff/research paths such as `.env`, keys, credentials, secrets, and tokens; known inline credential patterns pasted into chat are redacted on a best-effort basis, but arbitrary secrets may still be visible.

Supported command forms:

- `/goal <objective>` starts or replaces the session goal.
- `/goal status` reports objective, criteria, constraints, turn usage, evaluator reason, evidence, blocker, and recent history.
- `/goal help`, `/goal --help`, and `/goal -h` report usage for the command surface and completion marker.
- `/goal history` reports lifecycle events for the current session goal.
- `/goal pause`, `/goal resume`, and `/goal clear` control the active goal.
- `/goal observe` toggles observe mode; `/goal observe on` and `/goal observe off` set it explicitly.
- `/goal continue` or `/goal step` sends one explicit continuation, useful after an observe-mode verdict pause.
- `/goal edit <new objective>` revises the objective while preserving current turn limit and history; omitted success, constraints, and verify flags are cleared.
- `/goal clear` aliases: `stop`, `off`, `reset`, `none`, `cancel`.

Supported flags when setting a goal:

- `--max-turns <n>` limits auto-continue turns (default 100).
- `--success "criteria"` adds explicit success criteria.
- `--constraints "constraints"` or `--non-goals "constraints"` adds constraints and non-goals.
- `--verify "command"` records a build-agent verification directive. The plugin never executes it; the build agent runs it under normal permissions and the evaluator judges the transcript-visible result.
- `--observe` runs evaluator/researcher passes but pauses on not-met verdicts instead of auto-continuing. Use bare `--observe` to enable it, or inline boolean forms such as `--observe=on` and `--observe=off`.

Value flags support both `--flag value` and `--flag="multi word value"` forms. Boolean flags use bare or inline forms. Use `--` before objective text that contains literal `--flag` tokens. Goal state is persisted per project under `.opencode/goals/`.
