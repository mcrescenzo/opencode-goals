import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { readFileSync } from "node:fs";
import pkg from "../package.json" with { type: "json" };
import { parseCommandMarkdown, registerGoalCommand } from "../goals-core.js";

async function commandFixture(t, source) {
  const dir = await mkdtemp(path.join(tmpdir(), "goals-cmd-"));
  t.after(async () => { await rm(dir, { recursive: true, force: true }); });
  if (source !== undefined) {
    await mkdir(path.join(dir, "commands"), { recursive: true });
    await writeFile(path.join(dir, "commands", "goal.md"), source);
  }
  return dir;
}

test("parseCommandMarkdown splits frontmatter description from template body", () => {
  const out = parseCommandMarkdown("---\ndescription: Do a thing\n---\nBody $ARGUMENTS\n", "fallback");
  assert.equal(out.description, "Do a thing");
  assert.equal(out.template, "Body $ARGUMENTS\n");
});

test("parseCommandMarkdown normalizes CRLF command frontmatter", () => {
  const out = parseCommandMarkdown("---\r\ndescription: Manage goal\r\n---\r\nGoal $ARGUMENTS\r\n", "fallback");
  assert.equal(out.description, "Manage goal");
  assert.equal(out.template, "Goal $ARGUMENTS\n");
});

test("parseCommandMarkdown falls back when there is no frontmatter", () => {
  const out = parseCommandMarkdown("just a body", "fb");
  assert.equal(out.description, "fb");
  assert.equal(out.template, "just a body");
});

test("registerGoalCommand registers cfg.command.goal from a bundled commands/goal.md", async (t) => {
  const dir = await commandFixture(t, "---\ndescription: Manage goal\n---\nGoal $ARGUMENTS\n");
  const cfg = {};
  await registerGoalCommand(cfg, dir);
  assert.equal(cfg.command.goal.description, "Manage goal");
  assert.match(cfg.command.goal.template, /\$ARGUMENTS/);
});

test("registerGoalCommand does NOT clobber a user-provided goal command (dual-mode)", async (t) => {
  const dir = await commandFixture(t, "---\ndescription: bundled\n---\nbundled\n");
  const cfg = { command: { goal: { description: "user", template: "user" } } };
  await registerGoalCommand(cfg, dir);
  assert.equal(cfg.command.goal.description, "user");
});

test("registerGoalCommand degrades silently when the bundled file is missing (no throw at boot)", async (t) => {
  const dir = await commandFixture(t);
  const cfg = {};
  await registerGoalCommand(cfg, dir); // commands/goal.md absent
  assert.ok(cfg.command && typeof cfg.command === "object");
  assert.equal(cfg.command.goal, undefined);
});

test("the REAL bundled commands/goal.md registers and contains $ARGUMENTS", async () => {
  const cfg = {};
  await registerGoalCommand(cfg, path.dirname(import.meta.dirname));
  assert.ok(cfg.command.goal, "bundled commands/goal.md must register");
  assert.match(cfg.command.goal.template, /\$ARGUMENTS/);
});

test("scoped package is configured for public publish", () => {
  assert.equal(pkg.publishConfig?.access, "public");
  assert.ok(pkg.engines?.node, "must declare an engines.node floor");
});

test("README has no machine-absolute paths", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  assert.doesNotMatch(readme, /\/home\/[^\s`"']+/);
});

test("GoalPlugin config hook registers cfg.command.goal", async (t) => {
  const { GoalPlugin } = await import("../goals.js");
  // Advisor caveat: GoalPlugin construction runs loadPersistedState against `directory`. An empty
  // client stub is fine (verified: loadPersistedState ENOENTs to "missing" without touching client),
  // but use a CLEAN tmp dir — not process.cwd() — so a stray .opencode/goals/state.json can't make
  // the test state-dependent.
  const dir = await mkdtemp(path.join(tmpdir(), "goals-e2e-"));
  t.after(async () => { await rm(dir, { recursive: true, force: true }); });
  const hooks = await GoalPlugin({ client: {}, directory: dir });
  const cfg = { model: "anthropic/claude-x" };
  await hooks.config(cfg);
  assert.ok(cfg.command.goal, "config hook must self-register /goal");
});
