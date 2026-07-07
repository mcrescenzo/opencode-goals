# Evaluator Fixture Corpus

These fixtures are deterministic, no-network inputs for parser and prompt regression tests in `tests/goals-plugin.test.mjs`. They use realistic v1 SDK message shapes (`info.mode` for assistant agent identity, tool input/output under `state.input`/`state.output`, and `FileDiff` records with `file`, `before`, `after`, `additions`, `deletions`).

Live evaluator quality checks are intentionally skip-by-default because they spend model tokens and can be nondeterministic. A future live harness should load these fixtures, run the real hidden `goal-evaluator` against each bundle, compare to `expectedMet`, and require an explicit opt-in environment flag such as `GOALS_LIVE_EVAL=1`; it must not run as part of `node --test tests/goals-plugin.test.mjs` or `npm test`.
