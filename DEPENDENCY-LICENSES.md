# Dependency License Inventory

Last reviewed: 2026-07-07

This inventory covers the public package dependency tree pinned by `bun.lock` for
`@mcrescenzo/opencode-goals@0.1.0`. It is derived from an offline local review of:

- `package.json` direct dependency declarations;
- `bun.lock` pinned package names, versions, integrity hashes, and optional platform metadata; and
- installed `node_modules/**/package.json` license fields after `bun install` on linux x64.

No dependency version or lockfile entry was changed during this review beyond resolving the
declared `@opencode-ai/plugin` caret range.

## Summary

- Direct runtime dependency: `@opencode-ai/plugin@^1.17.7` (resolved to `1.17.14`). The plugin
  source imports no `@opencode-ai/*` module directly — the dependency is declared to pin the
  plugin-host contract version this package is written against, per house convention.
- Pinned lockfile packages reviewed: 30.
- Installed package manifests reviewed locally on linux x64: 25.
- License families observed in installed manifests: MIT, ISC, Apache-2.0, and one dual-licensed
  package (`json-schema`, `AFL-2.1 OR BSD-3-Clause`).
- GPL/AGPL/LGPL/copyleft licenses observed: **none**.
- Packages without license metadata in installed manifests: **none**.

## Limitations

`bun.lock` includes optional `@msgpackr-extract/*` prebuilt packages for platforms that are not
installed on this linux x64 review host. Their package manifests were therefore not locally available
for offline inspection. The installed linux x64 optional package from the same family declares MIT.
Before publishing a release that is explicitly validated for another platform, run this inventory check
from that platform (or review the package tarball metadata through an approved release process) and
update this file if any optional package differs.

## Inventory

| Package | Version | Relationship | License observed | Offline source | Notes |
|---|---:|---|---|---|---|
| `@opencode-ai/plugin` | 1.17.14 | direct runtime dependency | MIT | `node_modules/@opencode-ai/plugin/package.json` | Depends on `@ai-sdk/provider`, `@opencode-ai/sdk`, `effect`, `zod`. |
| `@ai-sdk/provider` | 3.0.8 | transitive | Apache-2.0 | `node_modules/@ai-sdk/provider/package.json` | Pulled by `@opencode-ai/plugin`. |
| `@opencode-ai/sdk` | 1.17.14 | transitive | MIT | `node_modules/@opencode-ai/sdk/package.json` | Pulled by `@opencode-ai/plugin`. |
| `@standard-schema/spec` | 1.1.0 | transitive | MIT | `node_modules/@standard-schema/spec/package.json` | Pulled by `effect`. |
| `cross-spawn` | 7.0.6 | transitive | MIT | `node_modules/cross-spawn/package.json` | Pulled by `@opencode-ai/sdk`. |
| `detect-libc` | 2.1.2 | transitive | Apache-2.0 | `node_modules/detect-libc/package.json` | Pulled by `node-gyp-build-optional-packages`. |
| `effect` | 4.0.0-beta.83 | transitive | MIT | `node_modules/effect/package.json` | Pulled by `@opencode-ai/plugin`. |
| `fast-check` | 4.8.0 | transitive | MIT | `node_modules/fast-check/package.json` | Pulled by `effect`. |
| `find-my-way-ts` | 0.1.6 | transitive | MIT | `node_modules/find-my-way-ts/package.json` | Pulled by `effect`. |
| `ini` | 7.0.0 | transitive | ISC | `node_modules/ini/package.json` | Pulled by `effect`. |
| `isexe` | 2.0.0 | transitive | ISC | `node_modules/isexe/package.json` | Pulled by `which`. |
| `json-schema` | 0.4.0 | transitive | AFL-2.1 OR BSD-3-Clause | `node_modules/json-schema/package.json` | Pulled by `@ai-sdk/provider`. |
| `kubernetes-types` | 1.30.0 | transitive | Apache-2.0 | `node_modules/kubernetes-types/package.json` | Pulled by `effect`. |
| `msgpackr` | 2.0.4 | transitive | MIT | `node_modules/msgpackr/package.json` | Pulled by `effect`. |
| `msgpackr-extract` | 3.0.4 | optional transitive | MIT | `node_modules/msgpackr-extract/package.json` | Optional native extraction helper for `msgpackr`. |
| `@msgpackr-extract/msgpackr-extract-linux-x64` | 3.0.4 | optional platform transitive | MIT | `node_modules/@msgpackr-extract/msgpackr-extract-linux-x64/package.json` | Installed/reviewed on this linux x64 host. |
| `@msgpackr-extract/msgpackr-extract-darwin-arm64` | 3.0.4 | optional platform transitive | not locally installed | `bun.lock` only | Platform package pinned for darwin arm64; see limitations. |
| `@msgpackr-extract/msgpackr-extract-darwin-x64` | 3.0.4 | optional platform transitive | not locally installed | `bun.lock` only | Platform package pinned for darwin x64; see limitations. |
| `@msgpackr-extract/msgpackr-extract-linux-arm` | 3.0.4 | optional platform transitive | not locally installed | `bun.lock` only | Platform package pinned for linux arm; see limitations. |
| `@msgpackr-extract/msgpackr-extract-linux-arm64` | 3.0.4 | optional platform transitive | not locally installed | `bun.lock` only | Platform package pinned for linux arm64; see limitations. |
| `@msgpackr-extract/msgpackr-extract-win32-x64` | 3.0.4 | optional platform transitive | not locally installed | `bun.lock` only | Platform package pinned for win32 x64; see limitations. |
| `multipasta` | 0.2.8 | transitive | MIT | `node_modules/multipasta/package.json` | Pulled by `effect`. |
| `node-gyp-build-optional-packages` | 5.2.2 | transitive | MIT | `node_modules/node-gyp-build-optional-packages/package.json` | Pulled by `msgpackr-extract`. |
| `path-key` | 3.1.1 | transitive | MIT | `node_modules/path-key/package.json` | Pulled by `cross-spawn`. |
| `pure-rand` | 8.4.1 | transitive | MIT | `node_modules/pure-rand/package.json` | Pulled by `fast-check`. |
| `shebang-command` | 2.0.0 | transitive | MIT | `node_modules/shebang-command/package.json` | Pulled by `cross-spawn`. |
| `shebang-regex` | 3.0.0 | transitive | MIT | `node_modules/shebang-regex/package.json` | Pulled by `shebang-command`. |
| `toml` | 4.1.2 | transitive | MIT | `node_modules/toml/package.json` | Pulled by `effect`. |
| `uuid` | 14.0.1 | transitive | MIT | `node_modules/uuid/package.json` | Pulled by `effect`. |
| `which` | 2.0.2 | transitive | ISC | `node_modules/which/package.json` | Pulled by `cross-spawn`. |
| `yaml` | 2.9.0 | transitive | ISC | `node_modules/yaml/package.json` | Pulled by `effect`. |
| `zod` | 4.1.8 | transitive | MIT | `node_modules/zod/package.json` | Pulled by `@opencode-ai/plugin`. |

## Maintenance check

Run the no-network inventory test after changing `package.json`, `bun.lock`, or installed dependency
metadata:

```bash
node --test tests/dependency-license-inventory.test.mjs
```

The check verifies that every pinned `bun.lock` package has an inventory row, that every installed
package manifest has a non-empty license field, that installed licenses do not match GPL/AGPL/LGPL
patterns, and that `DEPENDENCY-LICENSES.md` is included in the packed package file list.
