// OpenCode session SDK compatibility adapter.

export function sessionResponseData(result) {
  if (result && typeof result === "object" && Object.hasOwn(result, "data")) {
    return result.data;
  }
  return result;
}

export function sessionResponseError(result) {
  return result && typeof result === "object" && Object.hasOwn(result, "error")
    ? result.error
    : null;
}

function errorField(error, field) {
  if (!error || typeof error !== "object") return undefined;
  return error[field] ?? error.cause?.[field] ?? error.error?.[field] ?? error.response?.[field];
}

function errorText(error) {
  if (!error) return "";
  if (typeof error === "string") return error;
  const fields = [
    error.name,
    error.code,
    error.status,
    error.statusCode,
    error.message,
    errorField(error, "name"),
    errorField(error, "code"),
    errorField(error, "status"),
    errorField(error, "statusCode"),
    errorField(error, "message"),
  ];
  try {
    fields.push(JSON.stringify(error.body ?? error.data ?? error.response?.data ?? error.response?.body));
  } catch {}
  return fields.filter((value) => value != null).map(String).join(" ");
}

export function isSessionPathShapeIncompatibility(error) {
  const text = errorText(error).toLowerCase();
  if (!text) return false;
  if (/\b(abort|aborted|timeout|timed out|provider|model|auth|permission|rate|quota|token|tool|schema|format|json|parts|body|agent)\b/.test(text)) {
    return false;
  }

  const status = Number(errorField(error, "status") ?? errorField(error, "statusCode") ?? error?.status ?? error?.statusCode);
  const transportShapeStatus = status === 400 || status === 404 || /\b(bad\s*request|invalid\s*request|not\s*found|badrequest|invalidrequest|notfound|badrequesterror|invalidrequesterror|notfounderror|400|404)\b/.test(text);
  if (!transportShapeStatus) return false;

  // v1 option-object clients leave `/session/{id}` unresolved when called with v2 `{sessionID}`.
  // Some generated clients surface that as a terse BadRequest/NotFound without a field-level detail.
  if (/\b(path|route|url|param|parameter|sessionid|session id|\bid\b|required|missing|undefined|\{id\}|\{sessionid\})\b/.test(text)) {
    return true;
  }
  return /\b(badrequesterror|invalidrequesterror|notfounderror)\b/.test(text);
}

function hasUnresolvedSessionIDPath(result) {
  const url = String(result?.request?.url ?? result?.response?.url ?? "");
  if (!url) return false;
  return /\{(?:sessionid|id)\}/i.test(url) || /%7b(?:sessionid|id)%7d/i.test(url);
}

function sessionRequestOptions(ctx, options = {}) {
  const query = { directory: ctx.directory, ...(options.query ?? {}) };
  return { ...options, query };
}

export async function callOpenCodeSessionMethod(ctx, method, options = {}) {
  const session = ctx.client?.session;
  const fn = session?.[method];
  if (typeof fn !== "function") throw new TypeError(`OpenCode session.${method} is not available`);
  return fn.call(session, sessionRequestOptions(ctx, options));
}

export async function callOpenCodeSessionPathMethod(ctx, method, sessionID, options = {}) {
  const session = ctx.client?.session;
  const fn = session?.[method];
  if (typeof fn !== "function") throw new TypeError(`OpenCode session.${method} is not available`);

  const baseOptions = sessionRequestOptions(ctx, options);
  const primary = { ...baseOptions, path: { sessionID } };
  let result;
  try {
    result = await fn.call(session, primary);
  } catch (error) {
    if (!isSessionPathShapeIncompatibility(error)) throw error;
    return fn.call(session, { ...baseOptions, path: { id: sessionID } });
  }

  const error = sessionResponseError(result);
  if (hasUnresolvedSessionIDPath(result) || isSessionPathShapeIncompatibility(error)) {
    return fn.call(session, { ...baseOptions, path: { id: sessionID } });
  }
  return result;
}

export function openCodeSessionCreate(ctx, body, options = {}) {
  return callOpenCodeSessionMethod(ctx, "create", { ...options, body });
}

export function openCodeSessionPrompt(ctx, sessionID, body, options = {}) {
  return callOpenCodeSessionPathMethod(ctx, "prompt", sessionID, { ...options, body });
}

export function openCodeSessionPromptAsync(ctx, sessionID, body, options = {}) {
  return callOpenCodeSessionPathMethod(ctx, "promptAsync", sessionID, { ...options, body });
}

export function openCodeSessionMessages(ctx, sessionID, query = {}) {
  return callOpenCodeSessionPathMethod(ctx, "messages", sessionID, { query });
}

export function openCodeSessionDiff(ctx, sessionID, query = {}) {
  return callOpenCodeSessionPathMethod(ctx, "diff", sessionID, { query });
}

export function openCodeSessionAbort(ctx, sessionID, query = {}, options = {}) {
  return callOpenCodeSessionPathMethod(ctx, "abort", sessionID, { ...options, query });
}

export function openCodeSessionDelete(ctx, sessionID, query = {}, options = {}) {
  return callOpenCodeSessionPathMethod(ctx, "delete", sessionID, { ...options, query });
}
