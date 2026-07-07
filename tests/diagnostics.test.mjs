import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { createGoalDiagnostics, jsonLine } from "../diagnostics.js";
import { logPluginError } from "../goals-core.js";
import { diagnosticLines, tempRoot, withDiagnosticsRoot } from "./helpers.mjs";

test("goal diagnostics emit standardized redacted JSONL", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      await diagnostics.emit({
        level: "error",
        event: "goal_evaluation_failed",
        message: "Failed with Bearer abcdefghijklmnop",
        sessionID: "ses_1",
        operation: "evaluate_goal",
        error: new Error("token=abc123456789"),
        data: { apiKey: "sk-secretsecretsecret123", safe: true },
      });

      const lines = await diagnosticLines(diagRoot);
      assert.equal(lines.length, 1);
      const record = JSON.parse(lines[0]);
      assert.equal(record.schema, "opencode.plugin.diagnostic.v1");
      assert.equal(record.plugin, "goals");
      assert.equal(record.level, "error");
      assert.equal(record.event, "goal_evaluation_failed");
      assert.equal(record.sessionID, "ses_1");
      assert.equal(record.data.apiKey, "[redacted]");
      assert.doesNotMatch(lines[0], /abcdefghijklmnop|abc123456789|secretsecretsecret/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goal diagnostics are disabled and no-op on invalid storage", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED = "1";
      await createGoalDiagnostics({ directory: root }).emit({ level: "error", event: "disabled", message: "disabled" });
      assert.deepStrictEqual(await diagnosticLines(diagRoot), []);

      delete process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED;
      const fileRoot = path.join(diagRoot, "not-a-directory");
      await writeFile(fileRoot, "x", "utf8");
      process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR = fileRoot;
      const diagnostics = createGoalDiagnostics({ directory: root });
      await assert.doesNotReject(() => diagnostics.emit({ level: "error", event: "bad_storage", message: "bad" }));
      await diagnostics.emit({ level: "error", event: "after_failure", message: "suppressed" });
      assert.deepStrictEqual(await diagnosticLines(diagRoot), [], "storage failures latch diagnostics off and suppress later emits");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-zlv.71: diagnostics failures do not suppress primary plugin error logging", async () => {
  let appLogCalls = 0;
  let loggedEvent = "";
  await logPluginError(
    {
      app: {
        log: async (params) => {
          appLogCalls += 1;
          loggedEvent = params?.body?.extra?.event;
        },
      },
    },
    "synthetic failure",
    new Error("diagnostic path should not mask this"),
    {
      diagnostics: { emit: async () => { throw new Error("diagnostics unavailable"); } },
      event: "synthetic_failure",
      operation: "unit_test",
    },
  );

  assert.equal(appLogCalls, 1, "app.log still receives the plugin error after diagnostics.emit throws");
  assert.equal(loggedEvent, "synthetic_failure");
});

test("goals-pf3.8: diagnostics redaction scrubs compound secret identifiers like core redactInlineSecrets", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      // Compound identifiers (OPENAI_API_KEY, DB_PASSWORD, MY_PRIVATE_KEY) are missed by a
      // \b-anchored bare-name pattern because the secret token is preceded by an underscore; these
      // must be scrubbed in diagnostics exactly as goals-core.js redactInlineSecrets scrubs them.
      await diagnostics.emit({
        level: "warn",
        event: "compound_secret_check",
        message: "cfg OPENAI_API_KEY=sk_live_0123456789abcdef DB_PASSWORD=hunter2plus MY_PRIVATE_KEY=topsecretvalue1234 done",
      });

      const lines = await diagnosticLines(diagRoot);
      const record = JSON.parse(lines[0]);
      assert.match(record.message, /OPENAI_API_KEY=<redacted>/);
      assert.match(record.message, /DB_PASSWORD=<redacted>/);
      assert.match(record.message, /MY_PRIVATE_KEY=<redacted>/);
      assert.doesNotMatch(record.message, /sk_live_0123456789abcdef|hunter2plus|topsecretvalue1234/);

      await diagnostics.emit({
        level: "warn",
        event: "token_prefix_check",
        message: "tokens ghp_abcdefghijklmnopqrstuvwxyz0123 ghs_abcdefghijklmnopqrstuvwxyz0123 AKIAIOSFODNN7EXAMPLE",
      });
      const tokenRecord = JSON.parse((await diagnosticLines(diagRoot)).at(-1));
      assert.doesNotMatch(tokenRecord.message, /ghp_abcdefghijklmnopqrstuvwxyz0123|ghs_abcdefghijklmnopqrstuvwxyz0123|AKIAIOSFODNN7EXAMPLE/);
      assert.match(tokenRecord.message, /ghp_<redacted>/);
      assert.match(tokenRecord.message, /ghs_<redacted>/);
      assert.match(tokenRecord.message, /AKIA<redacted>/);

      await diagnostics.emit({
        level: "warn",
        event: "provider_token_prefix_check",
        message: "tokens glpat_abcdefghijklmnopqrstuvwxyz012345 gloas-abcdefghijklmnopqrstuvwxyz012345 glrt-abcdefghijklmnopqrstuvwxyz012345 npm_abcdefghijklmnopqrstuvwxyz012345 pypi-AgEIcHlwaS5vcmc0123456789abcdef",
      });
      const providerTokenRecord = JSON.parse((await diagnosticLines(diagRoot)).at(-1));
      assert.doesNotMatch(
        providerTokenRecord.message,
        /glpat_abcdefghijklmnopqrstuvwxyz012345|gloas-abcdefghijklmnopqrstuvwxyz012345|glrt-abcdefghijklmnopqrstuvwxyz012345|npm_abcdefghijklmnopqrstuvwxyz012345|pypi-AgEIcHlwaS5vcmc0123456789abcdef/,
      );
      assert.match(providerTokenRecord.message, /glpat_<redacted>/);
      assert.match(providerTokenRecord.message, /gloas_<redacted>/);
      assert.match(providerTokenRecord.message, /glrt_<redacted>/);
      assert.match(providerTokenRecord.message, /npm_<redacted>/);
      assert.match(providerTokenRecord.message, /pypi_<redacted>/);

      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnb2Fscy1nem0xOSIsInNjb3BlIjoidGVzdCJ9.dGhpc2lzYWZha2VzaWduYXR1cmV2YWx1ZQ";
      const sessionToken = "session_token_abcdefghijklmnopqrstuvwxyz0123456789";
      await diagnostics.emit({
        level: "warn",
        event: "bearerless_token_shape_check",
        message: `tokens ${jwt} ${sessionToken}`,
      });
      const bearerlessRecord = JSON.parse((await diagnosticLines(diagRoot)).at(-1));
      assert.doesNotMatch(bearerlessRecord.message, /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9|session_token_abcdefghijklmnopqrstuvwxyz0123456789/);
      assert.match(bearerlessRecord.message, /<redacted>/);
      assert.match(bearerlessRecord.message, /session_token_<redacted>/);

      await diagnostics.emit({
        level: "warn",
        event: "quoted_secret_check",
        message: 'quoted DB_PASSWORD="alpha beta gamma" API_TOKEN=\'delta epsilon zeta\' ESCAPED_PASSWORD=\\"one two three\\" done',
      });
      const quotedRecord = JSON.parse((await diagnosticLines(diagRoot)).at(-1));
      assert.match(quotedRecord.message, /DB_PASSWORD=<redacted>/);
      assert.match(quotedRecord.message, /API_TOKEN=<redacted>/);
      assert.match(quotedRecord.message, /ESCAPED_PASSWORD=<redacted>/);
      assert.doesNotMatch(quotedRecord.message, /alpha beta gamma|beta gamma|delta epsilon zeta|epsilon zeta|one two three|two three/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-zlv.31/zlv.114: diagnostics redact URL credentials and Cookie headers", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      const dsn = "postgres://dbuser:supersecretpass@db.example/app";
      const http = "https://user:verysecret@host.example/path";
      const cookie = "Cookie: session=secret-session-cookie; theme=dark";
      const setCookie = "Set-Cookie: sid=secret-set-cookie; HttpOnly; Path=/";

      await diagnostics.emit({
        level: "error",
        event: "credential_url_check",
        message: `provider failed at ${dsn} with ${cookie}`,
        error: new Error(`retry ${http} ${setCookie}`),
        data: {
          url: dsn,
          nested: { headers: `${cookie}\n${setCookie}` },
        },
      });

      const lines = await diagnosticLines(diagRoot);
      assert.equal(lines.length, 1);
      const record = JSON.parse(lines[0]);
      const serialized = JSON.stringify(record);
      assert.match(record.message, /postgres:\/\/<redacted>@db\.example\/app/);
      assert.match(record.message, /Cookie: <redacted>/);
      assert.match(record.error.message, /https:\/\/<redacted>@host\.example\/path/);
      assert.match(record.error.message, /Set-Cookie: <redacted>/);
      assert.match(record.data.url, /postgres:\/\/<redacted>@db\.example\/app/);
      assert.match(record.data.nested.headers, /Cookie: <redacted>/);
      assert.match(record.data.nested.headers, /Set-Cookie: <redacted>/);
      assert.doesNotMatch(serialized, /supersecretpass|verysecret|secret-session-cookie|secret-set-cookie/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-zlv.31: app.log error summaries redact URL credentials", async () => {
  const appLogs = [];
  await logPluginError(
    {
      app: {
        log: async (params) => {
          appLogs.push(params);
        },
      },
    },
    "synthetic diagnostic failure",
    new Error("connect ECONNREFUSED mongodb://user:diagnosticpass@mongo.example/admin"),
    { event: "diagnostic_url_failure", operation: "unit_test" },
  );

  assert.equal(appLogs.length, 1);
  const serialized = JSON.stringify(appLogs[0]);
  assert.match(serialized, /mongodb:\/\/<redacted>@mongo\.example\/admin/);
  assert.doesNotMatch(serialized, /diagnosticpass/);
});

test("goals-pf3.87: an oversized diagnostic record is capped so the emitted line never exceeds MAX_RECORD + 1", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      // Several near-MAX_STRING fields collectively exceed MAX_RECORD (16 KB) even after data/error
      // are dropped, exercising the final fallback cap.
      const big = "x".repeat(5000);
      await diagnostics.emit({
        level: "error",
        event: "oversized_record",
        message: big,
        sessionID: big,
        messageID: big,
        callID: big,
        tool: big,
        command: big,
      });

      const lines = await diagnosticLines(diagRoot);
      assert.equal(lines.length, 1);
      // MAX_RECORD is 16_000; the contract is that no emitted line exceeds MAX_RECORD + 1.
      assert.ok(lines[0].length <= 16_001, `line length ${lines[0].length} exceeds MAX_RECORD + 1`);
      // The capped line must still be valid JSON with the identifying schema/plugin fields.
      const record = JSON.parse(lines[0]);
      assert.equal(record.schema, "opencode.plugin.diagnostic.v1");
      assert.equal(record.plugin, "goals");
      assert.equal(record.event, "oversized_record");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-zlv.87: diagnostic jsonLine last-resort fallback remains valid JSON", () => {
  const record = {
    schema: "opencode.plugin.diagnostic.v1",
    ts: new Date().toISOString(),
    plugin: "goals",
    level: "error",
    event: "pathological_record",
    message: "x".repeat(5000),
  };
  for (let i = 0; i < 120; i += 1) {
    record[`field${i}`] = "x".repeat(1000);
  }

  const line = jsonLine(record);
  assert.ok(line.length <= 16_001, `line length ${line.length} exceeds MAX_RECORD + 1`);
  const parsed = JSON.parse(line);
  assert.equal(parsed.schema, "opencode.plugin.diagnostic.v1");
  assert.equal(parsed.plugin, "goals");
  assert.equal(parsed.event, "pathological_record");
  assert.equal(parsed.truncated, true);
});

test("goals-gzm.3: diagnostic jsonLine remains byte-bounded with multibyte unicode", () => {
  const line = jsonLine({
    schema: "opencode.plugin.diagnostic.v1",
    ts: new Date().toISOString(),
    plugin: "goals",
    level: "warn",
    event: "unicode_record",
    message: "\u754c".repeat(9000),
  });

  assert.ok(Buffer.byteLength(line, "utf8") <= 16_001, `line byte length ${Buffer.byteLength(line, "utf8")} exceeds MAX_RECORD + 1`);
  const parsed = JSON.parse(line);
  assert.equal(parsed.schema, "opencode.plugin.diagnostic.v1");
  assert.equal(parsed.plugin, "goals");
  assert.equal(parsed.event, "unicode_record");
});

test("diagnostics rotate the per-day JSONL file before appending past the file cap", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      await diagnostics.emit({ level: "info", event: "seed", message: "seed" });

      const [project] = await readdir(diagRoot);
      const pluginDir = path.join(diagRoot, project, "goals");
      const targetName = (await readdir(pluginDir)).find((file) => file.endsWith(".jsonl"));
      assert.ok(targetName, "initial diagnostics emit creates a jsonl target");
      const target = path.join(pluginDir, targetName);
      await writeFile(target, "x".repeat(5 * 1024 * 1024), { mode: 0o600 });

      await diagnostics.emit({ level: "warn", event: "after_rotation", message: "new current file" });

      assert.equal((await readFile(`${target}.1`, "utf8")).length, 5 * 1024 * 1024, "full prior diagnostics file is rotated to .1");
      const current = await readFile(target, "utf8");
      assert.match(current, /after_rotation/, "new record lands in a fresh diagnostics file");
      assert.doesNotMatch(current, /^x+$/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-gzm.64: diagnostics rotation rename failure latches diagnostics off without throwing", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      await diagnostics.emit({ level: "info", event: "seed", message: "seed" });

      const [project] = await readdir(diagRoot);
      const pluginDir = path.join(diagRoot, project, "goals");
      const targetName = (await readdir(pluginDir)).find((file) => file.endsWith(".jsonl"));
      assert.ok(targetName, "initial diagnostics emit creates a jsonl target");
      const target = path.join(pluginDir, targetName);
      await writeFile(target, "x".repeat(5 * 1024 * 1024), { mode: 0o600 });
      await mkdir(`${target}.1`);

      await assert.doesNotReject(() =>
        diagnostics.emit({ level: "warn", event: "rotation_rename_failed", message: "suppressed" }),
      );
      await diagnostics.emit({ level: "warn", event: "after_rotation_failure", message: "still suppressed" });

      const current = await readFile(target, "utf8");
      assert.equal(current.length, 5 * 1024 * 1024, "the active diagnostics file is left unchanged after rename failure");
      assert.doesNotMatch(current, /rotation_rename_failed|after_rotation_failure/, "failed rotation and later emits are suppressed");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-gzm.22: concurrent diagnostics rotation is serialized and stays enabled", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      await diagnostics.emit({ level: "info", event: "seed", message: "seed" });

      const [project] = await readdir(diagRoot);
      const pluginDir = path.join(diagRoot, project, "goals");
      const targetName = (await readdir(pluginDir)).find((file) => file.endsWith(".jsonl"));
      assert.ok(targetName, "initial diagnostics emit creates a jsonl target");
      const target = path.join(pluginDir, targetName);
      await writeFile(target, "x".repeat(5 * 1024 * 1024), { mode: 0o600 });

      await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          diagnostics.emit({ level: "warn", event: `concurrent_rotation_${index}`, message: "queued" }),
        ),
      );
      await diagnostics.emit({ level: "info", event: "after_concurrent_rotation", message: "still enabled" });

      const current = await readFile(target, "utf8");
      const records = current.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      assert.equal(records.filter((record) => /^concurrent_rotation_/.test(record.event)).length, 8);
      assert.equal(records.at(-1).event, "after_concurrent_rotation", "a later emit still writes after the rotation burst");
      assert.equal((await readFile(`${target}.1`, "utf8")).length, 5 * 1024 * 1024, "the full prior file is rotated once");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-pf3.96: diagnostics recursive redactor handles nested objects and circular references", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      const data = {
        level1: {
          level2: {
            inline: "OPENAI_API_KEY=sk_live_abcdefghijklmnop",
            token: "should_be_redacted_by_key_name",
            ok: "fine",
          },
        },
      };
      data.level1.level2.back = data; // circular reference
      await diagnostics.emit({ level: "info", event: "nested_recursive", message: "ok", data });

      const lines = await diagnosticLines(diagRoot);
      assert.equal(lines.length, 1);
      const record = JSON.parse(lines[0]);
      const level2 = record.data.level1.level2;
      assert.equal(level2.ok, "fine", "non-secret nested value survives");
      assert.match(level2.inline, /OPENAI_API_KEY=<redacted>/, "inline secret in a nested string is scrubbed");
      assert.doesNotMatch(level2.inline, /sk_live_abcdefghijklmnop/);
      assert.equal(level2.token, "[redacted]", "secret-named key is redacted recursively");
      assert.equal(level2.back, "[circular]", "the circular reference is bounded");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("goals-gzm.60: diagnostics object redaction stops before reading entries beyond the cap", async () => {
  await withDiagnosticsRoot(async (diagRoot) => {
    const root = await tempRoot();
    try {
      const diagnostics = createGoalDiagnostics({ directory: root });
      const data = {};
      for (let index = 0; index < 100; index += 1) {
        data[`field${index}`] = index;
      }
      Object.defineProperty(data, "field100", {
        enumerable: true,
        get() {
          throw new Error("post-cap getter should not be read");
        },
      });

      await diagnostics.emit({ level: "info", event: "wide_object", message: "ok", data });

      const lines = await diagnosticLines(diagRoot);
      assert.equal(lines.length, 1);
      const record = JSON.parse(lines[0]);
      assert.equal(record.data.field99, 99);
      assert.equal(record.data.field100, undefined, "post-cap entries are omitted without reading them");
      assert.equal(record.data.__truncated_entries, "unknown");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
