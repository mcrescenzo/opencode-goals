// Opt-in host-contract smoke for the hidden-session lifecycle.
//
// Normal `npm test` keeps this skipped so the suite remains token-free and does
// not require a local OpenCode host. Set OPENCODE_GOALS_HOST_SMOKE=1 to start a
// disposable `opencode serve --pure` process and drive the real session client.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import {
  createHiddenSession,
  hiddenSessionPrompt,
  openCodeSessionAbort,
  openCodeSessionCreate,
  openCodeSessionDelete,
  openCodeSessionMessages,
  openCodeSessionPrompt,
  sessionResponseData,
  sessionResponseError,
} from "../goals-core.js";

const RUN_HOST_SMOKE = process.env.OPENCODE_GOALS_HOST_SMOKE === "1";
const HOST_SMOKE_SKIP =
  "set OPENCODE_GOALS_HOST_SMOKE=1 to run against a local OpenCode host";

function responseSummary(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function assertNoSessionError(result, label) {
  const error = sessionResponseError(result);
  assert.equal(error, null, `${label} returned an OpenCode error: ${responseSummary(error)}`);
}

function assertAcceptedOrHostRuntimeError(result, label) {
  const error = sessionResponseError(result);
  if (!error) return;
  const summary = responseSummary(error);
  assert.match(
    summary,
    /provider|model|auth|credential|quota|rate|UnknownError|Unexpected server error/i,
    `${label} failed before reaching host/provider runtime: ${summary}`,
  );
}

function requireSessionID(result, label) {
  assertNoSessionError(result, label);
  const id = sessionResponseData(result)?.id;
  assert.equal(typeof id, "string", `${label} returned a session id`);
  assert.ok(id, `${label} returned a non-empty session id`);
  return id;
}

function requestSessionID(request) {
  return request?.path?.sessionID ?? request?.path?.id ?? null;
}

function instrumentSessionClient(client) {
  const calls = [];
  for (const name of ["create", "prompt", "abort", "delete", "messages"]) {
    const original = client.session?.[name];
    if (typeof original !== "function") continue;
    client.session[name] = async function instrumentedSessionMethod(request) {
      calls.push({ name, request });
      return original.call(this, request);
    };
  }
  return calls;
}

async function startPureOpenCodeServer({ timeoutMs }) {
  const command = process.env.OPENCODE_GOALS_HOST_SMOKE_CLI || "opencode";
  const env = { ...process.env };
  delete env.OPENCODE_CONFIG_CONTENT;
  if (process.env.OPENCODE_GOALS_HOST_SMOKE_CONFIG_CONTENT) {
    env.OPENCODE_CONFIG_CONTENT = process.env.OPENCODE_GOALS_HOST_SMOKE_CONFIG_CONTENT;
  }
  const proc = spawn(command, [
    "serve",
    "--pure",
    "--hostname=127.0.0.1",
    "--port=0",
    "--log-level=ERROR",
  ], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  const url = await new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      proc.kill("SIGTERM");
      reject(new Error(`Timed out waiting for OpenCode server after ${timeoutMs}ms\n${output}`));
    }, timeoutMs);

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };

    const onData = (chunk) => {
      output += chunk.toString();
      for (const line of output.split(/\r?\n/)) {
        const match = line.match(/opencode server listening.*\s(https?:\/\/[^\s]+)/);
        if (match) finish(resolve, match[1]);
      }
    };

    proc.stdout.on("data", onData);
    proc.stderr.on("data", onData);
    proc.once("error", (error) => finish(reject, error));
    proc.once("exit", (code, signal) => {
      finish(reject, new Error(`OpenCode server exited before startup: code=${code} signal=${signal}\n${output}`));
    });
  });

  return {
    url,
    async close() {
      if (proc.exitCode !== null || proc.killed) return;
      proc.kill("SIGTERM");
      await Promise.race([once(proc, "exit"), delay(1000)]);
    },
  };
}

test("hidden-session lifecycle works against a real OpenCode session client", {
  skip: RUN_HOST_SMOKE ? false : HOST_SMOKE_SKIP,
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "goals-host-contract-smoke-"));
  const serverTimeoutMs = Number(process.env.OPENCODE_GOALS_HOST_SMOKE_TIMEOUT_MS || 10_000);
  let server;
  let parentID = "";
  let manualChildID = "";

  try {
    const { createOpencodeClient } = await import("@opencode-ai/sdk");
    server = await startPureOpenCodeServer({ timeoutMs: serverTimeoutMs });
    const client = createOpencodeClient({ baseUrl: server.url, directory: root });
    const calls = instrumentSessionClient(client);
    const ctx = { directory: root, client };

    parentID = requireSessionID(
      await openCodeSessionCreate(ctx, { title: "opencode-goals host-contract parent" }),
      "parent session.create",
    );

    manualChildID = await createHiddenSession(ctx, parentID);
    assert.ok(manualChildID, "createHiddenSession creates a hidden child session through the real host");

    assertAcceptedOrHostRuntimeError(
      await openCodeSessionPrompt(ctx, manualChildID, {
        noReply: true,
        parts: [{ type: "text", text: "opencode-goals host smoke manual hidden child" }],
      }),
      "manual child session.prompt noReply",
    );
    assertAcceptedOrHostRuntimeError(await openCodeSessionAbort(ctx, manualChildID), "manual child session.abort");
    assertNoSessionError(await openCodeSessionDelete(ctx, manualChildID), "manual child session.delete");
    manualChildID = "";

    assertAcceptedOrHostRuntimeError(
      await hiddenSessionPrompt(ctx, parentID, { hiddenPromptTimeoutMs: 5_000 }, {
        noReply: true,
        parts: [{ type: "text", text: "opencode-goals host smoke hiddenSessionPrompt child" }],
      }),
      "hiddenSessionPrompt noReply",
    );

    const parentMessagesResult = await openCodeSessionMessages(ctx, parentID, { limit: 20 });
    assertNoSessionError(parentMessagesResult, "parent session.messages");
    const parentMessages = sessionResponseData(parentMessagesResult) ?? [];
    assert.doesNotMatch(
      JSON.stringify(parentMessages),
      /opencode-goals host smoke .* child/,
      "hidden child prompts do not land in the parent session transcript",
    );

    const promptTargets = calls.filter((call) => call.name === "prompt").map((call) => requestSessionID(call.request));
    assert.ok(promptTargets.length >= 2, "the smoke exercised real session.prompt requests");
    assert.ok(promptTargets.every((id) => id && id !== parentID), "hidden prompts target child sessions, not the parent");

    const abortTargets = calls.filter((call) => call.name === "abort").map((call) => requestSessionID(call.request));
    assert.ok(abortTargets.includes(manualChildID) || abortTargets.some((id) => id && id !== parentID), "the smoke exercised child session.abort");

    const deleteTargets = calls.filter((call) => call.name === "delete").map((call) => requestSessionID(call.request));
    assert.ok(deleteTargets.some((id) => id && id !== parentID), "the smoke exercised child session.delete");
  } finally {
    if (server && manualChildID) {
      try {
        const { createOpencodeClient } = await import("@opencode-ai/sdk");
        const client = createOpencodeClient({ baseUrl: server.url, directory: root });
        await openCodeSessionDelete({ directory: root, client }, manualChildID);
      } catch {}
    }
    if (server && parentID) {
      try {
        const { createOpencodeClient } = await import("@opencode-ai/sdk");
        const client = createOpencodeClient({ baseUrl: server.url, directory: root });
        await openCodeSessionDelete({ directory: root, client }, parentID);
      } catch {}
    }
    if (server) await server.close();
    await rm(root, { recursive: true, force: true });
  }
});
