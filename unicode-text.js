export function codePoints(value) {
  return Array.from(String(value || ""));
}

export function sliceCodePoints(value, start, end) {
  return codePoints(value).slice(start, end).join("");
}

export function truncateCodePoints(value, maxChars, suffix = "") {
  const chars = codePoints(value);
  if (chars.length <= maxChars) return String(value || "");
  return `${chars.slice(0, maxChars).join("")}${suffix}`;
}
