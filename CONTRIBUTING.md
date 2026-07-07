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
