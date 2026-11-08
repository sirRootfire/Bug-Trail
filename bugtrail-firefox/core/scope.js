// Scope enforcement. Fails closed: anything unparsable or unmatched is out of scope.
export function normalizeHost(input) {
  const v = String(input ?? '').trim();
  if (!v) return '';
  try { return new URL(v.includes('://') ? v : `https://${v}`).hostname.toLowerCase(); }
  catch { return v.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase(); }
}
function matches(host, rule) {
  const r = String(rule.hostname ?? '').toLowerCase().replace(/^\.+/, '');
  if (!r) return false;
  return rule.includeSubdomains ? host === r || host.endsWith(`.${r}`) : host === r;
}
export function isInScope(urlString, scopes = [], excluded = []) {
  try {
    const u = new URL(urlString);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    if (excluded.some((r) => r.enabled !== false && matches(host, r))) return false;
    return scopes.some((r) => r.enabled !== false && matches(host, r));
  } catch { return false; }
}
