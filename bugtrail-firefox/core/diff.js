// Semantic response comparison. Volatile values are normalised; ids/ownership fields are NOT.
const VOLATILE_KEY = /(^|[._-])(timestamp|time|date|created_?at|updated_?at|nonce|request[-_]?id|trace[-_]?id|csrf[-_]?token|etag|expires?)$/i;
const VOLATILE_HEADER = /^(date|set-cookie|x-request-id|x-trace-id|etag|age|server-timing|expires|content-length)$/i;
function flat(o, p = '', out = {}) { if (Array.isArray(o)) { out[`${p}#len`] = o.length; o.slice(0, 20).forEach((x, i) => flat(x, `${p}[${i}]`, out)); } else if (o && typeof o === 'object') { for (const [k, v] of Object.entries(o)) flat(v, p ? `${p}.${k}` : k, out); } else out[p] = o; return out; }
export function summarize(resp) {
  const ct = resp.contentType || ''; const body = resp.body ?? '';
  let json = null; if (/json/i.test(ct) || /^\s*[{\[]/.test(body)) { try { json = JSON.parse(body); } catch { json = null; } }
  const htmlTags = !json && /html/i.test(ct + body.slice(0, 200)) ? [...body.matchAll(/<(h1|h2|form|table|input|a)\b/gi)].map((m) => m[1].toLowerCase()).join(',') : null;
  return { status: resp.status, contentType: ct.split(';')[0], location: resp.location || null, size: body.length, json, htmlTags, keys: json && typeof json === 'object' ? Object.keys(flat(json)).filter((k) => !VOLATILE_KEY.test(k)).sort() : [], bodyAvailable: resp.bodyAvailable !== false && resp.body !== undefined };
}
export function compare(base, mod, ctx = {}) {
  const a = summarize(base), b = summarize(mod); const changes = [];
  if (a.status !== b.status) changes.push({ kind: 'status', detail: `${a.status} → ${b.status}`, matters: a.status >= 400 && b.status < 400 ? 'Access previously denied now succeeds' : 'Status differs' });
  if (a.contentType !== b.contentType) changes.push({ kind: 'content-type', detail: `${a.contentType} → ${b.contentType}`, matters: 'Different resource type returned' });
  if (a.location !== b.location) changes.push({ kind: 'redirect-location', detail: `${a.location ?? '—'} → ${b.location ?? '—'}`, matters: 'Redirect target differs' });
  if (a.json && b.json) {
    const fa = flat(a.json), fb = flat(b.json);
    for (const k of new Set([...Object.keys(fa), ...Object.keys(fb)])) {
      if (VOLATILE_KEY.test(k.split('.').pop())) continue;
      if (!(k in fa)) changes.push({ kind: 'field-added', field: k, matters: 'Field only present in modified response' });
      else if (!(k in fb)) changes.push({ kind: 'field-removed', field: k, matters: 'Field missing in modified response' });
      else if (String(fa[k]) !== String(fb[k])) changes.push({ kind: 'value-changed', field: k, matters: /id|owner|user|account|email|name|role/i.test(k) ? 'Ownership/identity-related value differs' : 'Value differs' });
    }
  } else if (a.htmlTags !== null && b.htmlTags !== null && a.htmlTags !== b.htmlTags) changes.push({ kind: 'html-structure', detail: 'Element structure differs', matters: 'Different page content' });
  if (a.size !== b.size && !(a.json && b.json)) changes.push({ kind: 'size', detail: `${a.size} → ${b.size} bytes`, matters: 'Body length differs' });
  if (ctx.modifiedId && mod.body && String(mod.body).includes(ctx.modifiedId)) changes.push({ kind: 'identifier-reflected', detail: 'Modified identifier appears in response body', matters: 'Response is tied to the substituted identifier' });
  return { base: strip(a), modified: strip(b), changes, identical: changes.length === 0 };
}
const strip = ({ json, ...r }) => r;
