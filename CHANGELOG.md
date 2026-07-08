# Changelog

## 0.1.1 - 2026-07-08

- Documentation-only release: README now leads with the goal-drift problem and
  adds a worked `/goal` example with toast and evaluator-verdict output;
  install/registration moved up; adds a "For AI agents" note consolidating the
  `[goal:evidence]` / `[goal:complete]` / `[goal:blocked]` marker contract.
- Relocated the hooks table and opencode-compatibility notes to `AGENTS.md`
  and the full test-suite breakdown to `CONTRIBUTING.md`. No runtime changes.

## 0.1.0 - Initial public release

- Adds the `/goal` command for a single persistent session goal.
- Registers hidden `goal-evaluator` and read-only `goal-researcher` agents.
- Persists per-workspace goal state under `.opencode/goals/`.
- Includes no-token package and runtime smoke tests for release validation.
- Targets Node.js `>=20.11.0` and the current/latest opencode runtime checked during release preparation.

No npm publish, git tag, or repository visibility change is implied by this changelog entry.
