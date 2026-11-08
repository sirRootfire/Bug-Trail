// Passive privilege / mass-assignment observation. Never sends anything.
const PRIV = /^(role[-_]?id|role|roles|is[-_]?admin|admin|permissions?|privileges?|user[-_]?type|account[-_]?type|access[-_]?level|tenant[-_]?id|owner[-_]?id|verified|approved|status|is[-_]?staff|is[-_]?superuser)$/i;
const ADMIN_PATH = /\/(admin|api\/admin|api\/users\/manage|api\/roles|manage)(\/|$)/i;
const PROFILE_PATH = /\/(profile|account|me|users?\/[^/]+|settings)(\/|$)/i;
export const isPrivField = (k) => PRIV.test(k);
export const isAdminPath = (p) => ADMIN_PATH.test(p);
function flatten(o, p = '', out = {}) { if (o && typeof o === 'object' && !Array.isArray(o)) for (const [k, v] of Object.entries(o)) flatten(v, p ? `${p}.${k}` : k, out); else out[p] = o; return out; }
export function observePrivilege({ method, url, requestBody, responseBody, identity, requestId }) {
  let path = ''; try { path = new URL(url).pathname; } catch { return []; }
  const writeMethod = ['POST', 'PUT', 'PATCH'].includes(String(method).toUpperCase());
  const parse = (b) => { try { return typeof b === 'string' ? JSON.parse(b) : b; } catch { return null; } };
  const req = flatten(parse(requestBody) ?? {}); const res = flatten(parse(responseBody) ?? {});
  const out = [];
  const keys = new Set([...Object.keys(req), ...Object.keys(res)]);
  for (const k of keys) {
    const leaf = k.split('.').pop();
    if (!PRIV.test(leaf)) continue;
    const sent = k in req; const returned = k in res;
    out.push({ field: k, identity: identity || null, requestId, endpoint: path, method, submittedByClient: sent, returnedByServer: returned && !sent ? true : returned, value: returned ? String(res[k]) : null, profileLike: PROFILE_PATH.test(path) && writeMethod, serverAccepted: null, persistenceVerified: false, reviewStatus: 'needs-review', note: sent ? 'Client submitted a privilege-related field' : 'Server exposes a privilege-related field (writability unknown)' });
  }
  return out;
}
