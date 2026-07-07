// Release gate: prove the actual `npm pack` tarball is self-contained and loads
// from a fresh external project. This catches three release-time failures that the
// repo-source tests cannot:
//
//   1. a `files` whitelist that omits a runtime file (e.g. commands/goal.md),
//   2. a bad/missing default export after the package is packed,
//   3. accidental parent-config assumptions baked into `import.meta.dirname`.
//
// It does all of this WITHOUT model calls, network, or credentials: it packs the
// tarball into a temp dir OUTSIDE the repo, extracts it, and dynamically imports
// the extracted entry so Node resolves every relative import purely from the
// packed tree. (No source file imports `@opencode-ai/plugin`, so the import does
// not need to resolve that dependency and stays offline.)
//
// `npm test` runs this automatically; it is the documented local + CI smoke.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import pkg from "../package.json" with { type: "json" };

const REPO_ROOT = path.resolve(new URL("../", import.meta.url).pathname);

// `tar` is universally available on the supported platforms (Node >=20.11 on
// linux/mac CI). If it is genuinely absent, skip loudly rather than fail opaquely.
function hasTar() {
  try {
    execFileSync("tar", ["--version"], { stdio: "ignore", encoding: "utf8" });
    return true;
  } catch {
    return false;
  }
}

test("npm pack produces a self-contained tarball that imports and registers /goal from outside the repo", async (t) => {
  if (!hasTar()) {
    t.skip("system `tar` not available; cannot extract packed tarball in this environment");
    return;
  }

  // Temp root OUTSIDE the repo: holds the tarball, the extracted package, and a
  // clean `directory` for GoalPlugin state so a stray .opencode/goals/state.json
  // can't make the assertion state-dependent (mirrors command-registration tests).
  const tmpRoot = await mkdtemp(path.join(tmpdir(), "goals-pack-smoke-"));
  try {
    // 1. Pack the real artifact (npm pack is the package-manager-policy-sanctioned
    //    artifact check) into the external temp dir — never the repo working tree.
    const packJson = execFileSync(
      "npm",
      ["pack", "--json", "--pack-destination", tmpRoot],
      { cwd: REPO_ROOT, encoding: "utf8" },
    );
    const packInfo = JSON.parse(packJson);
    assert.ok(Array.isArray(packInfo) && packInfo.length === 1, "npm pack --json returns one entry");
    const tarballPath = path.join(tmpRoot, packInfo[0].filename);
    await access(tarballPath, fsConstants.R_OK);
    assert.ok(packInfo[0].size > 0, "packed tarball must be non-empty");

    // 2. Extract into a fresh external project dir, then point at `package/`.
    const extractDir = path.join(tmpRoot, "extract");
    await mkdir(extractDir, { recursive: true });
    execFileSync("tar", ["-xf", tarballPath, "-C", extractDir], { encoding: "utf8" });
    const extractedPkgDir = path.join(extractDir, "package");

    // 3. Every runtime file the package advertises (plus manifest/LICENSE) must
    //    actually be inside the packed tarball — a `files` whitelist gap fails here.
    const expectedEntries = [...(pkg.files ?? []), "package.json", "LICENSE"];
    for (const entry of expectedEntries) {
      await access(path.join(extractedPkgDir, entry), fsConstants.R_OK);
    }

    // 4. The extracted manifest's main/exports must point at files that exist in
    //    the tarball, so `require("<pkg>")` / `import("<pkg>")` resolves downstream.
    const extractedManifest = JSON.parse(await readFile(path.join(extractedPkgDir, "package.json"), "utf8"));
    assert.equal(extractedManifest.main, pkg.main, "packed manifest preserves `main`");
    assert.deepEqual(extractedManifest.exports, pkg.exports, "packed manifest preserves `exports`");
    await access(path.join(extractedPkgDir, extractedManifest.main), fsConstants.R_OK);

    // 5. Dynamically import the EXTRACTED entry. Node resolves goals.js ->
    //    diagnostics.js/goals-core.js purely from the packed tree, so any omitted
    //    runtime file throws here. No network, no model calls, no credentials.
    const mod = await import(path.join(extractedPkgDir, "goals.js"));
    assert.equal(typeof mod.GoalPlugin, "function", "default export exposes GoalPlugin factory");

    // 6. End-to-end registration from the extracted tree: a clean `directory`
    //    keeps loadPersistedState state-independent, and the config hook must
    //    self-register /goal from the BUNDLED commands/goal.md using
    //    import.meta.dirname resolved INSIDE the extracted package (not the repo).
    const stateDir = await mkdtemp(path.join(tmpRoot, "state-"));
    const hooks = await mod.GoalPlugin({ client: {}, directory: stateDir });
    const cfg = { model: "smoke/no-model" };
    await hooks.config(cfg);
    assert.ok(cfg.command?.goal, "config hook registers cfg.command.goal from packed commands/goal.md");
    assert.match(cfg.command.goal.template, /\$ARGUMENTS/, "bundled goal command template is intact");
    // Hidden agents are part of the public registration contract; assert both so a
    // packed-tree import can't silently drop agent wiring.
    assert.ok(cfg.agent?.["goal-evaluator"], "config hook registers hidden goal-evaluator agent");
    assert.ok(cfg.agent?.["goal-researcher"], "config hook registers hidden goal-researcher agent");
  } finally {
    await rm(tmpRoot, { recursive: true, force: true });
  }
});

test("npm pack --dry-run advertises exactly the package runtime files (no tests, no runtime state)", () => {
  const dryRun = execFileSync(
    "npm",
    ["pack", "--dry-run", "--json"],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  const info = JSON.parse(dryRun);
  const paths = info[0].files.map((f) => f.path).sort();
  // The package intentionally ships only its runtime surface. Local runtime/agent
  // state (.opencode, .remember, .beads, node_modules, tests) must never be packed.
  const forbidden = paths.filter((p) =>
    /^(tests|node_modules|\.opencode|\.remember|\.beads|\.repo-review|diagnostics\.js\.map|goals-core\.js\.map)$/i.test(p) ||
    /\.(test|spec)\.m?js$/i.test(p),
  );
  assert.deepEqual(forbidden, [], `packed tarball leaks non-runtime files: ${forbidden.join(", ")}`);
  // Sanity: the essential runtime files are advertised.
  for (const required of ["goals.js", "goals-core.js", "goal-state.js", "diagnostics.js", "secret-redaction.js", "unicode-text.js", "commands/goal.md", "package.json", "README.md"]) {
    assert.ok(paths.includes(required), `packed tarball is missing advertised runtime file: ${required}`);
  }
});
