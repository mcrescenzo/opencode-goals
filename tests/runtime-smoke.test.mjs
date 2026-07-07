// Public-release zero-token runtime smoke for the Goals plugin.
//
// This deliberately drives the WIRED GoalPlugin hook surface rather than only the
// pure helpers: it constructs the plugin in a clean temp workspace, runs the
// startup-time config hook, and exercises non-generating /goal command paths.
// The fake client throws if any model/session prompt API is touched, so a pass is
// observable evidence that the smoke used zero model calls/tokens and did not
// depend on global provider configuration.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { GoalPlugin } from "../goals.js";
import { states, tombstones } from "../goals-core.js";

function resetModuleRuntime() {
  states.clear();
  tombstones.clear();
}

function zeroTokenClient(calls = []) {
  const fail = (name) => async (...args) => {
    calls.push({ name, args });
    throw new Error(`runtime smoke must not call client.session.${name}`);
  };
  return {
    tui: {
      showToast: async (...args) => calls.push({ name: "tui.showToast", args }),
    },
    app: {
      log: async (...args) => calls.push({ name: "app.log", args }),
    },
    session: {
      messages: fail("messages"),
      diff: fail("diff"),
      prompt: fail("prompt"),
      promptAsync: fail("promptAsync"),
      create: fail("create"),
      abort: fail("abort"),
      delete: fail("delete"),
    },
  };
}

function text(output) {
  return (output.parts ?? []).map((part) => part.text || "").join("\n");
}

test("runtime config smoke registers /goal command and locked-down hidden agents with no provider config", async () => {
  resetModuleRuntime();
  const root = await mkdtemp(path.join(tmpdir(), "goals-runtime-smoke-"));
  const calls = [];
  try {
    const hooks = await GoalPlugin({ directory: root, client: zeroTokenClient(calls) });
    const model = { providerID: "zero-token", modelID: "runtime-smoke" };
    const cfg = { model };

    await hooks.config(cfg);

    assert.ok(cfg.command?.goal, "config hook registers bundled /goal command");
    assert.match(cfg.command.goal.template, /\$ARGUMENTS/, "bundled /goal command template is intact");

    const evaluator = cfg.agent?.["goal-evaluator"];
    assert.ok(evaluator, "config hook registers hidden goal-evaluator");
    assert.equal(evaluator.hidden, true);
    assert.equal(evaluator.mode, "primary");
    assert.equal(evaluator.model, model, "goal-evaluator inherits session model without hard-coding a provider");
    assert.equal(evaluator.temperature, 0);
    assert.equal(evaluator.maxSteps, 1);
    assert.equal(evaluator.permission["*"], "deny");
    for (const tool of ["read", "glob", "grep", "list", "lsp", "edit", "bash", "task", "webfetch", "websearch", "skill", "question", "todowrite", "external_directory"]) {
      assert.equal(evaluator.permission[tool], "deny", `goal-evaluator denies ${tool}`);
    }

    const researcher = cfg.agent?.["goal-researcher"];
    assert.ok(researcher, "config hook registers hidden goal-researcher");
    assert.equal(researcher.hidden, true);
    assert.equal(researcher.mode, "primary");
    assert.equal(researcher.model, model, "goal-researcher inherits session model without hard-coding a provider");
    assert.equal(researcher.temperature, 0);
    assert.equal(researcher.maxSteps, 8);
    assert.equal(researcher.permission["*"], "deny");
    assert.equal(researcher.permission.glob, "deny", "goal-researcher cannot enumerate broad glob results");
    assert.equal(researcher.permission.list, "deny", "goal-researcher cannot enumerate directory listings");
    assert.equal(researcher.permission.lsp, "deny", "goal-researcher cannot use unrestricted LSP access");
    assert.equal(researcher.permission.edit, "deny");
    assert.equal(researcher.permission.bash, "deny");
    assert.equal(researcher.permission.task, "deny");
    assert.equal(researcher.permission.webfetch, "deny");
    assert.equal(researcher.permission.read["*"], "allow", "goal-researcher read is read-only allow-by-default");
    assert.equal(researcher.permission.read["**/.env"], "deny", "goal-researcher denies secret paths");
    assert.equal(researcher.permission.grep["**/*.pem"], "deny", "goal-researcher denies credential-like grep paths");

    assert.deepEqual(calls, [], "config smoke made no client/model calls");
  } finally {
    resetModuleRuntime();
    await rm(root, { recursive: true, force: true });
  }
});

test("runtime command smoke exercises status/help without model calls or persisted state", async () => {
  resetModuleRuntime();
  const root = await mkdtemp(path.join(tmpdir(), "goals-runtime-smoke-"));
  const calls = [];
  try {
    const hooks = await GoalPlugin({ directory: root, client: zeroTokenClient(calls) });
    await hooks.config({ model: "zero-token/runtime-smoke" });

    const statusOutput = {};
    await hooks["command.execute.before"](
      { command: "goal", arguments: "status", sessionID: "runtime-smoke-status" },
      statusOutput,
    );
    assert.match(text(statusOutput), /Report this \/goal status concisely/);
    assert.match(text(statusOutput), /No active \/goal/);

    const helpOutput = {};
    await hooks["command.execute.before"](
      { command: "goal", arguments: "help", sessionID: "runtime-smoke-help" },
      helpOutput,
    );
    assert.match(text(helpOutput), /Report this \/goal help concisely/);
    assert.match(text(helpOutput), /\/goal <objective>/);

    assert.deepEqual(calls, [], "status/help smoke made no client/model calls; observable token cost is zero");
    assert.equal(states.size, 0, "status/help smoke does not create active runtime goal state");
    assert.equal(tombstones.size, 0, "status/help smoke does not create tombstones");
  } finally {
    resetModuleRuntime();
    await rm(root, { recursive: true, force: true });
  }
});
