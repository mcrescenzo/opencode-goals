# Changelog

## 0.1.0 - Initial public release

- Adds the `/goal` command for a single persistent session goal.
- Registers hidden `goal-evaluator` and read-only `goal-researcher` agents.
- Persists per-workspace goal state under `.opencode/goals/`.
- Includes no-token package and runtime smoke tests for release validation.
- Targets Node.js `>=20.11.0` and the current/latest opencode runtime checked during release preparation.

No npm publish, git tag, or repository visibility change is implied by this changelog entry.
