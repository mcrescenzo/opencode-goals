const DEFAULT_MARKER = "[redacted]";
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const STANDALONE_SESSION_TOKEN_RE = /\b((?:sess(?:ion)?|sid|csrf|xsrf|jwt)(?:[-_]?token)?[-_])[A-Za-z0-9_-]{16,}\b/gi;
const STANDALONE_PROVIDER_TOKEN_RE = /\b(glpat|gloas|glrt|npm|pypi)[-_][A-Za-z0-9_-]{10,}/g;

export function redactInlineSecretText(value, options = {}) {
  const marker = String(options.marker ?? DEFAULT_MARKER);
  let out = String(value || "");

  out = out.replace(
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    `-----BEGIN PRIVATE KEY-----${marker}-----END PRIVATE KEY-----`,
  );
  out = out.replace(/\bBearer\s+[A-Za-z0-9._~+\/=-]+=*/gi, `Bearer ${marker}`);
  // goals-2j0: HTTP auth schemes are case-insensitive (RFC 7235), so redact Basic credentials for
  // lowercase/uppercase/mixed-case scheme spellings, consistent with the Bearer/Cookie redactors above.
  out = out.replace(/\bBasic\s+[A-Za-z0-9+\/=]{8,}/gi, `Basic ${marker}`);
  out = out.replace(/\b(Set-Cookie|Cookie)\s*:\s*[^\r\n]+/gi, `$1: ${marker}`);
  out = out.replace(/\b([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]{4,}@/g, `$1${marker}@`);
  out = out.replace(/\b(sk|pk|ghp|gho|ghu|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{10,}/g, `$1_${marker}`);
  out = out.replace(STANDALONE_PROVIDER_TOKEN_RE, `$1_${marker}`);
  out = out.replace(JWT_RE, marker);
  out = out.replace(STANDALONE_SESSION_TOKEN_RE, (_match, prefix) => `${prefix}${marker}`);
  out = out.replace(/\bAKIA[0-9A-Z]{12,}\b/g, `AKIA${marker}`);
  out = out.replace(
    /\b([A-Za-z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTHORIZATION|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|CREDENTIAL|PRIVATE[_-]?KEY)[A-Za-z0-9_-]*)\b["']?\s*[:=]\s*(?:\\?"(?:\\.|[^"\\]){4,}\\?"|\\?'(?:\\.|[^'\\]){4,}\\?'|[^\s"'`,;]{4,})/gi,
    (_match, key) => `${key}=${marker}`,
  );
  return out;
}
