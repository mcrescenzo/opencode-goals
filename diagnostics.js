import { createHash } from "node:crypto";
import { appendFile, chmod, lstat, mkdir, realpath, rename } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { redactInlineSecretText } from "./secret-redaction.js";
import { codePoints, truncateCodePoints } from "./unicode-text.js";

const SCHEMA = "opencode.plugin.diagnostic.v1";
const PLUGIN = "goals";
const LEVELS = new Set(["debug", "info", "warn", "error"]);
const MAX_STRING = 4_000;
const MAX_RECORD = 16_000;
const MAX_FILE = 5 * 1024 * 1024;
const MAX_DEPTH = 6;
const MAX_ENTRIES = 100;
const SECRET_KEY_RE = /(^|_|-|\.)(authorization|cookie|password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|refresh[_-]?token|serverPassword)($|_|-|\.)/i;
const appendQueues = new Map();

function truncateString(value, maxChars, suffix = "") {
  return truncateCodePoints(value, maxChars, suffix);
}

function redactText(value) {
  if (value === undefined || value === null) return "";
  const text = redactInlineSecretText(value, { marker: "<redacted>" });
  const chars = codePoints(text);
  if (chars.length <= MAX_STRING) return text;
  return `${chars.slice(0, MAX_STRING).join("")}\n[truncated ${chars.length - MAX_STRING} chars]`;
}

function redactValue(value, seen = new WeakSet(), depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return String(value);
  if (typeof value === "function") return "[function]";
  if (typeof value !== "object") return redactText(String(value));
  if (seen.has(value)) return "[circular]";
  if (depth >= MAX_DEPTH) return "[max-depth]";
  seen.add(value);
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ENTRIES).map((item) => redactValue(item, seen, depth + 1));
    if (value.length > MAX_ENTRIES) items.push(`[${value.length - MAX_ENTRIES} more items]`);
    return items;
  }
  const out = {};
  let count = 0;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (count >= MAX_ENTRIES) {
      out.__truncated_entries = "unknown";
      break;
    }
    const item = value[key];
    out[key] = SECRET_KEY_RE.test(String(key)) ? "[redacted]" : redactValue(item, seen, depth + 1);
    count += 1;
  }
  return out;
}

export function summarizeError(error) {
  if (!error) return undefined;
  if (typeof error === "string") return { message: redactText(error) };
  return redactValue({
    name: error.name || error.constructor?.name || "Error",
    message: error.message || String(error),
    code: error.code,
  });
}

function diagnosticsRoot() {
  if (process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR) return path.resolve(process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DIR);
  const base = process.env.XDG_STATE_HOME ? path.resolve(process.env.XDG_STATE_HOME) : path.join(os.homedir(), ".local", "state");
  return path.join(base, "opencode", "plugin-diagnostics");
}

function safeName(value, fallback = "project") {
  return (String(value || fallback).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 40) || fallback);
}

async function projectKey(directory) {
  const resolved = path.resolve(directory || process.cwd());
  let canonical = resolved;
  try {
    canonical = await realpath(resolved);
  } catch {}
  const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 16);
  return `${safeName(path.basename(canonical || resolved))}-${hash}`;
}

function datePart(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function truncateFields(record, budget) {
  const out = {};
  for (const [key, value] of Object.entries(record)) {
    out[key] = typeof value === "string" ? truncateString(value, budget, "…[truncated]") : value;
  }
  return out;
}

function recordFits(text) {
  return Buffer.byteLength(text, "utf8") <= MAX_RECORD;
}

export function jsonLine(record) {
  let text = JSON.stringify(record);
  if (recordFits(text)) return `${text}\n`;
  const compact = { ...record, data: record.data === undefined ? undefined : "[omitted: record too large]" };
  text = JSON.stringify(compact);
  if (recordFits(text)) return `${text}\n`;
  const reduced = { ...compact, message: redactText(compact.message).slice(0, 1000), error: compact.error ? summarizeError(compact.error) : undefined };
  text = JSON.stringify(reduced);
  if (recordFits(text)) return `${text}\n`;
  // pf3.87: final guarantee — a pathological record with many near-MAX_STRING fields (sessionID,
  // messageID, callID, tool, ...) can still exceed MAX_RECORD after the reductions above. Cap every
  // string field to a small budget so the line is always bounded; hard-cap the raw text as an
  // unreachable last resort so an emitted line can never exceed MAX_RECORD + 1.
  text = JSON.stringify(truncateFields(reduced, 200));
  if (recordFits(text)) return `${text}\n`;
  return `${JSON.stringify({
    schema: record.schema || SCHEMA,
    ts: record.ts,
    plugin: record.plugin || PLUGIN,
    level: record.level,
    event: record.event,
    message: "Diagnostic record exceeded maximum size after redaction; fields were omitted.",
    truncated: true,
  })}\n`;
}

async function rotateIfNeeded(target, line) {
  const lineBytes = Buffer.byteLength(line, "utf8");
  try {
    const stats = await lstat(target);
    if (stats.size + lineBytes > MAX_FILE) {
      await rename(target, `${target}.1`);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function appendDiagnosticLine(target, line) {
  const previous = appendQueues.get(target) || Promise.resolve();
  const current = previous.catch(() => {}).then(async () => {
    await rotateIfNeeded(target, line);
    await appendFile(target, line, { mode: 0o600 });
    try { await chmod(target, 0o600); } catch {}
  });
  appendQueues.set(target, current);
  try {
    await current;
  } finally {
    if (appendQueues.get(target) === current) appendQueues.delete(target);
  }
}

export function createGoalDiagnostics(ctx = {}) {
  let disabled = process.env.OPENCODE_PLUGIN_DIAGNOSTICS_DISABLED === "1";
  const directory = ctx.directory || process.cwd();
  let filePromise;

  async function filePath() {
    if (!filePromise) {
      filePromise = (async () => {
        const key = await projectKey(directory);
        const dir = path.join(diagnosticsRoot(), key, PLUGIN);
        await mkdir(dir, { recursive: true, mode: 0o700 });
        try { await chmod(dir, 0o700); } catch {}
        return path.join(dir, `${PLUGIN}-${datePart()}-${process.pid}.jsonl`);
      })();
    }
    return filePromise;
  }

  return {
    async emit(input = {}) {
      if (disabled) return;
      try {
        const record = redactValue({
          schema: SCHEMA,
          ts: new Date().toISOString(),
          plugin: PLUGIN,
          level: LEVELS.has(input.level) ? input.level : "info",
          event: input.event || "plugin_event",
          message: input.message || "",
          sessionID: input.sessionID,
          messageID: input.messageID,
          callID: input.callID,
          tool: input.tool,
          hook: input.hook,
          command: input.command,
          operation: input.operation,
          outcome: input.outcome,
          durationMs: input.durationMs,
          error: summarizeError(input.error),
          data: input.data,
        });
        const target = await filePath();
        const line = jsonLine(record);
        await appendDiagnosticLine(target, line);
      } catch {
        disabled = true;
      }
    },
  };
}
