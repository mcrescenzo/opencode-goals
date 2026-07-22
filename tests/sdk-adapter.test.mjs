import assert from "node:assert/strict";
import test from "node:test";

import {
  hiddenSessionPrompt,
  responseText,
} from "../goals-core.js";
import * as goalsCore from "../goals-core.js";
import {
  callOpenCodeSessionMethod,
  callOpenCodeSessionPathMethod,
  isSessionPathShapeIncompatibility,
  openCodeSessionAbort,
  openCodeSessionCreate,
  openCodeSessionDelete,
  openCodeSessionDiff,
  openCodeSessionMessages,
  openCodeSessionPrompt,
  openCodeSessionPromptAsync,
  sessionResponseData,
  sessionResponseError,
} from "../opencode-session-adapter.js";
import { fakeClient, pathShapeError, tempRoot } from "./helpers.mjs";

test("goals-7cee: goals-core preserves the extracted session adapter exports", () => {
  assert.equal(typeof hiddenSessionPrompt, "function", "core-only hidden session behavior remains exported from goals-core");
  for (const [name, helper] of Object.entries({
    callOpenCodeSessionMethod,
    callOpenCodeSessionPathMethod,
    isSessionPathShapeIncompatibility,
    openCodeSessionAbort,
    openCodeSessionCreate,
    openCodeSessionDelete,
    openCodeSessionDiff,
    openCodeSessionMessages,
    openCodeSessionPrompt,
    openCodeSessionPromptAsync,
    sessionResponseData,
    sessionResponseError,
  })) {
    assert.equal(goalsCore[name], helper, `goals-core re-exports the adapter's ${name} binding`);
  }
});

test("goals-gzm.73: responseText reads raw top-level message parts without a data wrapper", () => {
  assert.equal(
    responseText({ parts: [{ type: "text", text: ' {"met":false,"reason":"raw","next":"continue"} ' }] }),
    '{"met":false,"reason":"raw","next":"continue"}',
  );
});

test("goals-v2-migration: session client adapter sends v2 option-object path.sessionID first", async () => {
  const root = await tempRoot();
  const calls = { create: [], prompt: [], promptAsync: [], diff: [], messages: [], abort: [], delete: [] };
  const client = {
    session: {
      create: async (request) => { calls.create.push(request); return { data: { id: "hidden-child" } }; },
      prompt: async (request) => { calls.prompt.push(request); return { data: { parts: [{ type: "text", text: "ok" }] } }; },
      promptAsync: async (request) => { calls.promptAsync.push(request); return {}; },
      diff: async (request) => { calls.diff.push(request); return { data: [] }; },
      messages: async (request) => { calls.messages.push(request); return { data: [] }; },
      abort: async (request) => { calls.abort.push(request); return {}; },
      delete: async (request) => { calls.delete.push(request); return {}; },
    },
  };
  const ctx = { directory: root, client };

  const promptBody = { agent: "goal-evaluator", parts: [{ type: "text", text: "judge" }] };
  const createController = new AbortController();
  await openCodeSessionCreate(ctx, { parentID: "parent", title: "/goal hidden evaluation" }, { signal: createController.signal });
  await openCodeSessionPrompt(ctx, "ses_v2", promptBody);
  await openCodeSessionPromptAsync(ctx, "ses_v2", { agent: "build", parts: [{ type: "text", text: "continue" }] });
  await openCodeSessionDiff(ctx, "ses_v2");
  await openCodeSessionMessages(ctx, "ses_v2", { limit: 3 });
  await openCodeSessionAbort(ctx, "ses_v2");
  await openCodeSessionDelete(ctx, "ses_v2");

  assert.deepStrictEqual(calls.create[0], {
    body: { parentID: "parent", title: "/goal hidden evaluation" },
    query: { directory: root },
    signal: createController.signal,
  }, "session.create has no path fallback; it keeps the option-object body/query seam");
  for (const method of ["prompt", "promptAsync", "diff", "messages", "abort", "delete"]) {
    assert.deepStrictEqual(calls[method][0].path, { sessionID: "ses_v2" }, `session.${method} uses v2 path.sessionID first`);
    assert.equal(calls[method][0].query.directory, root, `session.${method} preserves workspace directory routing`);
  }
  assert.equal(calls.prompt[0].body, promptBody, "session.prompt preserves body by reference through the adapter");
  assert.equal(calls.messages[0].query.limit, 3, "session.messages preserves caller query parameters");
});

test("goals-v2-migration: observed v1 path.id fallback is bounded to request-shape incompatibility", async () => {
  const root = await tempRoot();
  const calls = { prompt: [], promptAsync: [], diff: [], messages: [], abort: [], delete: [] };
  const client = {
    session: Object.fromEntries(Object.entries(calls).map(([method, methodCalls]) => [
      method,
      async (request) => {
        methodCalls.push(request);
        if (methodCalls.length === 1) return pathShapeError("route /session/{id} not found for sessionID path");
        if (method === "diff" || method === "messages") return { data: [] };
        if (method === "prompt") return { data: { parts: [{ type: "text", text: "ok" }] } };
        return {};
      },
    ])),
  };
  const ctx = { directory: root, client };
  const controller = new AbortController();
  const promptBody = { agent: "goal-evaluator", parts: [{ type: "text", text: "judge" }] };

  await openCodeSessionPrompt(ctx, "ses_v1", promptBody, { signal: controller.signal });
  await openCodeSessionPromptAsync(ctx, "ses_v1", { agent: "build", parts: [{ type: "text", text: "continue" }] });
  await openCodeSessionDiff(ctx, "ses_v1");
  await openCodeSessionMessages(ctx, "ses_v1", { limit: 5 });
  await openCodeSessionAbort(ctx, "ses_v1");
  await openCodeSessionDelete(ctx, "ses_v1");

  for (const [method, methodCalls] of Object.entries(calls)) {
    assert.equal(methodCalls.length, 2, `session.${method} retries once on path-shape incompatibility`);
    assert.deepStrictEqual(methodCalls[0].path, { sessionID: "ses_v1" }, `session.${method} tries v2 path first`);
    assert.deepStrictEqual(methodCalls[1].path, { id: "ses_v1" }, `session.${method} falls back to observed v1 path.id`);
    assert.equal(methodCalls[1].query.directory, root, `session.${method} fallback preserves directory routing`);
  }
  assert.equal(calls.prompt[1].body, promptBody, "fallback prompt preserves the exact body object");
  assert.equal(calls.prompt[1].signal, controller.signal, "fallback prompt preserves AbortSignal");
  assert.equal(calls.messages[1].query.limit, 5, "fallback messages preserves caller query parameters");
});

test("goals-gzm.2: thrown path-shape exceptions trigger the bounded v1 path.id fallback", async () => {
  const root = await tempRoot();
  const calls = [];
  const client = {
    session: {
      prompt: async (request) => {
        calls.push(request);
        if (calls.length === 1) {
          const error = new Error("route /session/{id} not found for sessionID path");
          error.name = "NotFoundError";
          error.status = 404;
          throw error;
        }
        return { data: { parts: [{ type: "text", text: "ok" }] } };
      },
    },
  };
  const controller = new AbortController();
  const body = { agent: "goal-evaluator", parts: [{ type: "text", text: "judge" }] };

  const result = await openCodeSessionPrompt(
    { directory: root, client },
    "ses_throw_v1",
    body,
    { signal: controller.signal, query: { limit: 1 } },
  );

  assert.equal(result.data.parts[0].text, "ok", "the fallback result is returned after a thrown path-shape error");
  assert.equal(calls.length, 2, "the adapter retries exactly once for thrown path-shape incompatibility");
  assert.deepStrictEqual(calls[0].path, { sessionID: "ses_throw_v1" }, "the first call uses the public v2 path.sessionID shape");
  assert.deepStrictEqual(calls[1].path, { id: "ses_throw_v1" }, "the fallback call uses the observed v1 path.id shape");
  assert.equal(calls[1].body, body, "fallback prompt preserves the exact body object");
  assert.equal(calls[1].signal, controller.signal, "fallback prompt preserves AbortSignal");
  assert.deepStrictEqual(calls[1].query, { directory: root, limit: 1 }, "fallback prompt preserves merged query parameters");
});

test("goals-v2-migration: unresolved sessionID request URLs trigger v1 fallback without broad UnknownError retry", async () => {
  const root = await tempRoot();
  const deleteCalls = [];
  const concreteCalls = [];
  const client = {
    session: {
      delete: async (request) => {
        deleteCalls.push(request);
        if (deleteCalls.length === 1) {
          return {
            error: { name: "UnknownError", data: { message: "Unexpected server error. Check server logs for details." } },
            request: { url: "http://127.0.0.1:4096/session/%7Bid%7D" },
          };
        }
        return { data: true, request: { url: "http://127.0.0.1:4096/session/ses_v1" } };
      },
      abort: async (request) => {
        concreteCalls.push(request);
        return {
          error: { name: "UnknownError", data: { message: "Unexpected server error. Check server logs for details." } },
          request: { url: "http://127.0.0.1:4096/session/ses_v2/abort" },
        };
      },
    },
  };

  const deleteResult = await openCodeSessionDelete({ directory: root, client }, "ses_v1");
  const abortResult = await openCodeSessionAbort({ directory: root, client }, "ses_v2");

  assert.deepStrictEqual(deleteCalls.map((request) => request.path), [
    { sessionID: "ses_v1" },
    { id: "ses_v1" },
  ], "an unresolved {sessionID} URL is concrete evidence for v1 path.id fallback");
  assert.equal(deleteResult.data, true, "the fallback result is returned");
  assert.equal(concreteCalls.length, 1, "UnknownError on a concrete URL is not retried broadly");
  assert.equal(abortResult.error.name, "UnknownError", "the original concrete-url UnknownError is preserved");
});

test("goals-v2-migration: prompt model errors are not retried as v1 fallback calls", async () => {
  const root = await tempRoot();
  const calls = { prompt: [], promptAsync: [] };
  const client = {
    session: {
      prompt: async (request) => {
        calls.prompt.push(request);
        return { error: { name: "ProviderError", message: "model failed before producing a response" } };
      },
      promptAsync: async (request) => {
        calls.promptAsync.push(request);
        return { error: { name: "ProviderError", message: "model failed before producing a response" } };
      },
    },
  };

  const promptResult = await openCodeSessionPrompt(
    { directory: root, client },
    "ses_model_error",
    { agent: "goal-evaluator", parts: [{ type: "text", text: "judge" }] },
  );
  const asyncResult = await openCodeSessionPromptAsync(
    { directory: root, client },
    "ses_model_error",
    { agent: "build", parts: [{ type: "text", text: "continue" }] },
  );

  assert.equal(calls.prompt.length, 1, "provider/model errors must not double-send hidden prompts through fallback");
  assert.equal(calls.promptAsync.length, 1, "provider/model errors must not double-send continuation prompts through fallback");
  assert.deepStrictEqual(calls.prompt[0].path, { sessionID: "ses_model_error" }, "the hidden prompt attempt is still v2-shaped");
  assert.deepStrictEqual(calls.promptAsync[0].path, { sessionID: "ses_model_error" }, "the continuation prompt attempt is still v2-shaped");
  assert.equal(promptResult.error.name, "ProviderError", "the original prompt error is preserved");
  assert.equal(asyncResult.error.name, "ProviderError", "the original promptAsync error is preserved");
});

test("goals-v2-migration: shape classifier excludes abort/timeouts and provider errors", () => {
  assert.equal(isSessionPathShapeIncompatibility({ name: "BadRequestError", message: "missing path sessionID" }), true);
  assert.equal(isSessionPathShapeIncompatibility({ name: "NotFoundError", message: "route /session/{id}/message not found" }), true);
  assert.equal(isSessionPathShapeIncompatibility({ name: "AbortError", message: "The user aborted a request" }), false);
  assert.equal(isSessionPathShapeIncompatibility({ name: "TimeoutError", message: "Hidden /goal prompt timed out." }), false);
  assert.equal(isSessionPathShapeIncompatibility({ name: "ProviderError", message: "model failed" }), false);
});
