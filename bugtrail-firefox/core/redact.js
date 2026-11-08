// Redaction helpers: secrets are never displayed or exported in full.
export const SENSITIVE_KEY = /authorization|cookie|set-cookie|token|secret|passw(or)?d|passwd|api[-_]?key|csrf|session/i;
export const PLACEHOLDER = /^(\*+|•+|x{3,}|\.{3,}|#+|-{3,}|\[?(hidden|masked|redacted|none|null|undefined)\]?|<.*>|\{\{.*\}\}|password|your[-_ ]?password)$/i;

export function maskSecret(value) {
  const v = String(value ?? '');
  if (!v) return '';
  if (v.length <= 4) return '••••';
  return `${v.slice(0, 1)}••••••${v.slice(-1)} (len ${v.length})`;
}
export function maskId(value) {
  const v = String(value ?? '');
  return v.length > 6 ? `${v.slice(0, 3)}••••${v.slice(-3)}` : v;
}
export function isPlaceholder(value) {
  const v = String(value ?? '').trim();
  return v === '' || PLACEHOLDER.test(v);
}
export function sanitizeHeaders(headers) {
  const out = {};
  for (const h of headers ?? []) {
    const k = h.name.toLowerCase();
    out[k] = SENSITIVE_KEY.test(k) ? '[redacted]' : String(h.value ?? '').slice(0, 300);
  }
  return out;
}
export function sanitizeUrl(urlString) {
  try {
    const u = new URL(urlString);
    u.searchParams.forEach((val, key) => { if (SENSITIVE_KEY.test(key)) u.searchParams.set(key, '[redacted]'); });
    return u.toString();
  } catch { return String(urlString); }
}
