import { rmSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { persistQueues, resetGoalToastHeartbeatForTests, states, tombstones } from "../goals-core.js";
import { GoalPlugin } from "../goals.js";

// clearRuntimeState was the only non-core helper on the former test bridge; it is a trivial
// wrapper over the shared module-level `states` map now imported directly from goals-core.js.
export const clearRuntimeState = () => {
  states.clear();
  persistQueues.clear();
  tombstones.clear();
  resetGoalToastHeartbeatForTests();
};

export function fakeClient(overrides = {}) {
  return {
    tui: { showToast: async () => {} },
    app: { log: async () => {} },
    session: {
      messages: async () => ({ data: [] }),
      diff: async () => ({ data: [] }),
      prompt: async () => ({ data: { parts: [{ type: "text", text: '{"met":false,"reason":"no","next":"continue"}' }] } }),
      promptAsync: async () => ({}),
      // Hidden evaluator/researcher prompts run in an ephemeral child session (goals-runaway). Default
      // these so the child-session path is exercised; individual tests can still override them.
      create: async () => ({ data: { id: "hidden-child" } }),
      abort: async () => ({}),
      delete: async () => ({}),
      ...(overrides.session ?? {}),
    },
    ...(overrides.client ?? {}),
  };
}

const tempRoots = new Set();
let tempRootCleanupRegistered = false;

function registerTempRootCleanup() {
  if (tempRootCleanupRegistered) return;
  tempRootCleanupRegistered = true;
  process.once("exit", () => {
    for (const root of tempRoots) {
      rmSync(root, { recursive: true, force: true });
    }
    tempRoots.clear();
  });
}

export async function tempRoot() {
  registerTempRootCleanup();
  const root = await mkdtemp(path.join(os.tmpdir(), "goal-plugin-test-"));
  tempRoots.add(root);
  return root;
}

export async function pluginFor(root, client = fakeClient()) {
  return GoalPlugin({ directory: root, client });
}

export function pathShapeError(message = "missing required sessionID path parameter") {
  return { error: { name: "BadRequestError", message } };
}

export function commandInput(sessionID, args) {
  return { command: "goal", arguments: args, sessionID };
}

export function textOutput(output) {
  return (output.parts ?? []).map((part) => part.text).join("\n");
}

export function assistantMessage(text, overrides = {}) {
  return {
    role: "assistant",
    id: overrides.id ?? "assistant-1",
    parts: [{ type: "text", text }],
    info: { role: "assistant", id: overrides.id ?? "assistant-1", ...(overrides.info ?? {}) },
    ...overrides,
  };
}

export async function withDiagnosticsRoot(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "goal-diagnostics-test-"));
  const previous = process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR;
  const previousDisabled = process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED;
  process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR = dir;
  delete process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED;
  try {
    return await fn(dir);
  } finally {
    if (previous === undefined) delete process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR;
    else process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR = previous;
    if (previousDisabled === undefined) delete process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED;
    else process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED = previousDisabled;
    await rm(dir, { recursive: true, force: true });
  }
}

export async function diagnosticLines(root) {
  const projects = await readdir(root);
  const lines = [];
  for (const project of projects) {
    const pluginDir = path.join(root, project, "goals");
    let files;
    try { files = await readdir(pluginDir); } catch { files = []; }
    for (const file of files) {
      if (!file.endsWith(".jsonl")) continue;
      const content = await readFile(path.join(pluginDir, file), "utf8");
      lines.push(...content.trim().split(/\r?\n/).filter(Boolean));
    }
  }
  return lines;
}
