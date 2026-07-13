import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import pkg from "../package.json" with { type: "json" };

const ROOT = path.resolve(import.meta.dirname, "..");
const COPYLEFT_PATTERN = /\b(?:AGPL|GPL|LGPL)(?:[- ]?\d+(?:\.\d+)?)?\b/i;

function lockPackageSpecs(lockText) {
  // goals-6hj7: tolerate bun.lock indentation/whitespace differences (the prior exact-4-space regex
  // could return [] for a validly-formatted lockfile, making the coverage loop pass vacuously). The
  // non-empty sanity assertion in the calling test is the loud-failure backstop.
  return [...lockText.matchAll(/^\s+"([^"]+)": \["([^"]+)"/gm)].map((match) => match[2]).sort();
}

function nameVersionFromSpec(spec) {
  const at = spec.lastIndexOf("@");
  assert.ok(at > 0, `lock package spec must include @version: ${spec}`);
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

function inventoryRows(markdown) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .map((line) => {
      const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
      return {
        name: cells[0]?.replace(/^`|`$/g, ""),
        version: cells[1],
        license: cells[3],
      };
    });
}

// goals-a6c1: walk node_modules recursively so nested package-local node_modules manifests are
// audited too (the prior shallow scan missed node_modules/<pkg>/node_modules/<dep>/package.json).
// Skip symlinks, .bin, and hidden/admin dirs for safe, deterministic traversal. `dir` defaults to the
// repo root but is parameterized so the boundary behavior can be regression-tested with a temp fixture.
async function installedPackageJsonFiles(dir = ROOT) {
  const nodeModules = path.join(dir, "node_modules");
  if (!existsSync(nodeModules)) return [];
  const files = new Set();

  async function visitPackage(pkgDir) {
    const file = path.join(pkgDir, "package.json");
    if (existsSync(file)) files.add(file);
    // nested transitive deps installed under this package's own node_modules
    await walkNodeModules(path.join(pkgDir, "node_modules"));
  }

  async function walkNodeModules(nmDir) {
    let entries;
    try {
      entries = await readdir(nmDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.isSymbolicLink()) continue;
      if (ent.name === ".bin" || ent.name.startsWith(".")) continue;
      const child = path.join(nmDir, ent.name);
      if (ent.name.startsWith("@")) {
        // scoped: each child directory is a package
        let scopedEntries;
        try {
          scopedEntries = await readdir(child, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const scoped of scopedEntries) {
          if (!scoped.isDirectory() || scoped.isSymbolicLink()) continue;
          await visitPackage(path.join(child, scoped.name));
        }
      } else {
        await visitPackage(child);
      }
    }
  }

  await walkNodeModules(nodeModules);
  return [...files].sort();
}

test("dependency license inventory covers every pinned bun.lock package", async () => {
  // This package declares one runtime dependency (`@opencode-ai/plugin`), so a
  // `bun.lock` pins its resolved transitive tree. Skip only if no lockfile is
  // present (e.g. a fresh checkout before the first `bun install`).
  const lockPath = path.join(ROOT, "bun.lock");
  if (!existsSync(lockPath)) return;

  const lock = await readFile(lockPath, "utf8");
  const inventory = await readFile(path.join(ROOT, "DEPENDENCY-LICENSES.md"), "utf8");
  const rows = new Map(inventoryRows(inventory).map((row) => [`${row.name}@${row.version}`, row]));

  const specs = lockPackageSpecs(lock);
  // goals-6hj7: fail loudly if extraction returns no specs from a non-empty lockfile, rather than
  // letting the loop below pass vacuously and mask a real coverage gap.
  assert.ok(specs.length > 0, "bun.lock package extraction must be non-empty for a non-empty lockfile");
  for (const spec of specs) {
    const { name, version } = nameVersionFromSpec(spec);
    assert.ok(rows.has(`${name}@${version}`), `inventory missing pinned lock package ${name}@${version}`);
  }
});

test("installed dependency manifests have non-copyleft license metadata", async () => {
  const files = await installedPackageJsonFiles();
  // Skip only when nothing is installed yet (e.g. before the first `bun install`);
  // otherwise every installed manifest's license metadata is audited below.
  if (files.length === 0) return;

  for (const file of files) {
    const manifest = JSON.parse(await readFile(file, "utf8"));
    assert.ok(manifest.license, `${manifest.name ?? file} must declare a license in package.json`);
    assert.doesNotMatch(
      String(manifest.license),
      COPYLEFT_PATTERN,
      `${manifest.name}@${manifest.version} declares a copyleft license needing review`,
    );
  }
});

test("dependency license inventory stays repo-only and is excluded from the packed package file allowlist", () => {
  assert.ok(existsSync(path.join(ROOT, "DEPENDENCY-LICENSES.md")), "DEPENDENCY-LICENSES.md must remain tracked in git");
  assert.ok(!pkg.files.includes("DEPENDENCY-LICENSES.md"), "DEPENDENCY-LICENSES.md is not one of the permitted files[] categories and must not ship in the npm tarball");
});

test("CI workflow pins GitHub Actions to immutable commit SHAs", async () => {
  const workflow = await readFile(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const uses = [...workflow.matchAll(/^\s*uses:\s*([^@\s]+)@([^\s#]+)/gm)];
  assert.ok(uses.length > 0, "workflow must contain at least one action");
  for (const [, action, ref] of uses) {
    assert.match(ref, /^[a-f0-9]{40}$/i, `${action} must be pinned to a full-length commit SHA`);
  }
});

test("CI workflow disables checkout credential persistence for PR-controlled steps", async () => {
  const workflow = await readFile(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const checkoutStep = workflow.match(
    /-\s+name:\s*Checkout[\s\S]*?uses:\s+actions\/checkout@[^\n]+[\s\S]*?(?=\n\s*-\s+name:|\n\s*$)/,
  )?.[0];

  assert.ok(checkoutStep, "workflow must contain an actions/checkout step");
  assert.match(
    checkoutStep,
    /^\s*persist-credentials:\s*false\s*$/m,
    "actions/checkout must not persist the GitHub token into local git config",
  );
});

test("CI workflow disables dependency lifecycle scripts during Bun install", async () => {
  const workflow = await readFile(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const bunInstall = workflow.match(/^\s*run:\s*bun install[^\n]*$/m)?.[0] ?? "";

  assert.ok(bunInstall, "workflow must install dependencies with Bun");
  assert.match(
    bunInstall,
    /\s--ignore-scripts(?:\s|$)/,
    "Bun install in CI must disable dependency lifecycle scripts",
  );
});

test("CI workflow syntax-checks every shipped root JavaScript file", async () => {
  const workflow = await readFile(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const syntaxStep = workflow.match(
    /-\s+name:\s*Syntax checks[\s\S]*?(?=\n\s*-\s+name:|\n\s*$)/,
  )?.[0];
  const shippedRootJs = pkg.files.filter((file) => /^[^/]+\.js$/.test(file)).sort();
  const checked = [...(syntaxStep ?? "").matchAll(/^\s*node --check\s+(\S+)\s*$/gm)]
    .map((match) => match[1])
    .sort();

  assert.ok(syntaxStep, "workflow must contain a Syntax checks step");
  assert.deepStrictEqual(checked, shippedRootJs, "Syntax checks must cover every shipped root JavaScript file");
});

test("CI workflow does not use a frozen Bun install without a committed lockfile", async () => {
  const workflow = await readFile(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  const hasBunLock = existsSync(path.join(ROOT, "bun.lock")) || existsSync(path.join(ROOT, "bun.lockb"));

  if (!hasBunLock) {
    assert.doesNotMatch(workflow, /bun install[^\n]*--frozen-lockfile/, "no-lockfile packages must not use frozen Bun installs in CI");
  }
});

test("goals-a6c1: installedPackageJsonFiles audits nested package-local node_modules and skips .bin", async () => {
  const tmp = await mkdtemp(path.join(tmpdir(), "license-nested-"));
  try {
    const nm = (rel) => path.join(tmp, "node_modules", rel);
    const manifest = (name, license) => JSON.stringify({ name, version: "1.0.0", license });

    // direct dependency
    await mkdir(nm("direct-pkg"), { recursive: true });
    await writeFile(nm("direct-pkg/package.json"), manifest("direct-pkg", "MIT"));

    // nested transitive dependency: direct-pkg/node_modules/transitive-pkg
    await mkdir(nm("direct-pkg/node_modules/transitive-pkg"), { recursive: true });
    await writeFile(nm("direct-pkg/node_modules/transitive-pkg/package.json"), manifest("transitive-pkg", "MIT"));

    // nested scoped transitive dependency: direct-pkg/node_modules/@scope/scoped-transitive
    await mkdir(nm("direct-pkg/node_modules/@scope/scoped-transitive"), { recursive: true });
    await writeFile(nm("direct-pkg/node_modules/@scope/scoped-transitive/package.json"), manifest("@scope/scoped-transitive", "MIT"));

    // deeply nested: transitive-pkg has its own transitive
    await mkdir(nm("direct-pkg/node_modules/transitive-pkg/node_modules/deep-pkg"), { recursive: true });
    await writeFile(nm("direct-pkg/node_modules/transitive-pkg/node_modules/deep-pkg/package.json"), manifest("deep-pkg", "MIT"));

    // .bin administrative directory MUST be skipped even though it has a package.json
    await mkdir(nm(".bin"), { recursive: true });
    await writeFile(nm(".bin/package.json"), manifest("should-be-skipped", "GPL-3.0"));

    const files = await installedPackageJsonFiles(tmp);

    assert.ok(files.some((f) => f.includes("direct-pkg")), "direct manifests are still included");
    assert.ok(files.some((f) => f.includes("transitive-pkg")), "nested transitive manifests under package-local node_modules are included");
    assert.ok(files.some((f) => f.includes("@scope/scoped-transitive")), "nested scoped transitive manifests are included");
    assert.ok(files.some((f) => f.includes("deep-pkg")), "deeply nested transitive manifests are included");
    assert.ok(!files.some((f) => f.includes(".bin")), ".bin administrative directory is skipped");
    assert.ok(!files.some((f) => f.includes("should-be-skipped")), ".bin contents never reach the license audit");
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("goals-6hj7: lockPackageSpecs tolerates whitespace differences and returns [] for empty input", () => {
  // The prior exact-4-space regex silently returned [] for otherwise-valid formatting; the flexible
  // matcher must recover specs across indentation widths. Real bun.lock entries are shaped
  // `<indent>"<bare-name>": ["<name>@<version>", "", ...]`; lockPackageSpecs returns the array's first
  // element (the name@version spec), so fixtures mirror that shape.
  const spec = (indent) =>
    `\n${indent}"left-pad": ["left-pad@1.0.0", "", {}, "sha512-integrityhash"]\n`;

  assert.deepStrictEqual(lockPackageSpecs(spec("    ")), ["left-pad@1.0.0"], "4-space indentation parses");
  assert.deepStrictEqual(lockPackageSpecs(spec("  ")), ["left-pad@1.0.0"], "2-space indentation parses");
  assert.deepStrictEqual(lockPackageSpecs(spec("\t")), ["left-pad@1.0.0"], "tab indentation parses");
  assert.deepStrictEqual(lockPackageSpecs(spec("    ")), lockPackageSpecs(spec("  ")), "indentation does not change extracted specs");
  assert.deepStrictEqual(lockPackageSpecs("no package specs here\n"), [], "a lockfile with no specs yields [] not an error");
});
