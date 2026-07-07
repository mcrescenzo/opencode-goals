import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import pkg from "../package.json" with { type: "json" };

const ROOT = path.resolve(import.meta.dirname, "..");
const COPYLEFT_PATTERN = /\b(?:AGPL|GPL|LGPL)(?:[- ]?\d+(?:\.\d+)?)?\b/i;

function lockPackageSpecs(lockText) {
  return [...lockText.matchAll(/^    "([^"]+)": \["([^"]+)"/gm)].map((match) => match[2]).sort();
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

async function installedPackageJsonFiles() {
  const nodeModules = path.join(ROOT, "node_modules");
  if (!existsSync(nodeModules)) return [];
  const files = [];
  for (const ent of await readdir(nodeModules, { withFileTypes: true })) {
    if (!ent.isDirectory() || ent.name.startsWith(".")) continue;
    const dir = path.join(nodeModules, ent.name);
    if (ent.name.startsWith("@")) {
      for (const scoped of await readdir(dir, { withFileTypes: true })) {
        if (!scoped.isDirectory()) continue;
        const file = path.join(dir, scoped.name, "package.json");
        if (existsSync(file)) files.push(file);
      }
      continue;
    }
    const file = path.join(dir, "package.json");
    if (existsSync(file)) files.push(file);
  }
  return files.sort();
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

  for (const spec of lockPackageSpecs(lock)) {
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
