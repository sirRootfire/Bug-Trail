// Identifier discovery with provenance. Never generates or guesses identifiers.
import { maskId, SENSITIVE_KEY } from './redact.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_G = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ID_FIELD = /^(id|uid|uuid|guid|(user|account|order|invoice|file|document|doc|profile|org|organization|tenant|owner|role|resource|author|customer|member|post|item)[-_]?id)$/i;
const ID_HINT = /(^|[._-])(id|uuid|guid)$|Id$/;
const NOT_ID = /^(page|limit|offset|size|count|year|month|day|port|version|lang|q|sort|order_by)$/i;

export function classifyValue(v) {
  const s = String(v);
  if (UUID.test(s)) return 'uuid';
  if (/^\d{1,18}$/.test(s)) return 'numeric';
  if (/^[0-9a-f]{24}$/i.test(s)) return 'objectid';
  if (/^[A-Za-z0-9_-]{16,64}$/.test(s) && /\d/.test(s) && /[A-Za-z]/.test(s)) return 'opaque';
  if (/^[a-z0-9][a-z0-9-]{2,40}$/i.test(s)) return 'slug';
  return null;
}
function confidence(type, field, method) {
  if (type === 'uuid') return 'high';
  if (field && (ID_FIELD.test(field) || ID_HINT.test(field))) return type === 'numeric' || type === 'slug' ? 'high' : 'medium';
  return type === 'numeric' ? 'low' : 'low';
}
function make({ value, type, field, location, method, endpoint, identity, source, ts, context }) {
  return { id: `${type}:${value}`, value: String(value), masked: maskId(value), type, field: field || null, location, discoveryMethod: method, endpoint, identity: identity || null, source: source || null, timestamp: ts || Date.now(), confidence: confidence(type, field, method), context: context || null };
}
function accept(field, value) {
  if (field && SENSITIVE_KEY.test(field)) return false;
  if (field && NOT_ID.test(field)) return false;
  const type = classifyValue(value);
  if (!type) return false;
  if (type === 'numeric' || type === 'slug') return Boolean(field && (ID_FIELD.test(field) || ID_HINT.test(field)));
  return true;
}
export function fromUrl(urlString, ctx) {
  const out = [];
  try {
    const u = new URL(urlString);
    const parts = u.pathname.split('/').filter(Boolean);
    parts.forEach((p, i) => {
      const type = classifyValue(decodeURIComponent(p));
      const prev = parts[i - 1];
      if (type === 'uuid' || type === 'objectid' || (type === 'numeric' && prev)) {
        out.push(make({ ...ctx, value: p, type, field: prev ? `${prev}` : null, location: `path[${i}]`, method: 'url-path', context: prev || null }));
      }
    });
    u.searchParams.forEach((val, key) => { if (accept(key, val)) out.push(make({ ...ctx, value: val, type: classifyValue(val), field: key, location: `query.${key}`, method: 'url-query' })); });
  } catch { /* ignore */ }
  return out;
}
export function fromJson(obj, ctx, method = 'json-body', prefix = '') {
  const out = [];
  const walk = (v, path, key, depth) => {
    if (depth > 8 || v == null) return;
    if (Array.isArray(v)) { v.slice(0, 50).forEach((x, i) => walk(x, `${path}[${i}]`, key, depth + 1)); return; }
    if (typeof v === 'object') { for (const [k, c] of Object.entries(v)) walk(c, path ? `${path}.${k}` : k, k, depth + 1); return; }
    if (typeof v === 'string' || typeof v === 'number') {
      if (accept(key, v)) out.push(make({ ...ctx, value: v, type: classifyValue(v), field: key, location: path, method }));
    }
  };
  walk(obj, prefix, null, 0);
  return out;
}
export function fromGraphql(body, ctx) {
  try {
    const p = typeof body === 'string' ? JSON.parse(body) : body;
    const vars = p?.variables ?? {};
    return fromJson(vars, ctx, 'graphql-variables', 'variables');
  } catch { return []; }
}
export function fromForm(text, ctx) {
  const out = [];
  try { new URLSearchParams(text).forEach((v, k) => { if (accept(k, v)) out.push(make({ ...ctx, value: v, type: classifyValue(v), field: k, location: `form.${k}`, method: 'form-body' })); }); } catch { /* ignore */ }
  return out;
}
// HTML: UUIDs found in links/attributes are tied to their link context (e.g. author/profile links).
export function fromHtml(html, ctx) {
  const out = [];
  const text = String(html ?? '');
  const linkRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]{0,120}?)<\/a>/gi;
  let m;
  while ((m = linkRe.exec(text))) {
    const href = m[1]; const label = m[2].replace(/<[^>]+>/g, '').trim().slice(0, 60);
    const ids = href.match(UUID_G) || [];
    for (const id of ids) {
      const pre = href.slice(0, href.indexOf(id)).split(/[/?=&]/).filter(Boolean).pop() || null;
      out.push(make({ ...ctx, value: id, type: 'uuid', field: pre, location: `html:a[href]`, method: 'html-link', context: label ? `link "${label}"${pre ? ` → ${pre}` : ''}` : (pre || 'link') }));
    }
  }
  const attrRe = /\b(data-[\w-]*(?:id|uuid|user|author)[\w-]*)\s*=\s*["']([^"']+)["']/gi;
  while ((m = attrRe.exec(text))) {
    if (classifyValue(m[2]) === 'uuid') out.push(make({ ...ctx, value: m[2], type: 'uuid', field: m[1], location: `html:${m[1]}`, method: 'html-attribute', context: m[1] }));
  }
  const seen = new Set();
  return out.filter((o) => (seen.has(o.id + o.location) ? false : (seen.add(o.id + o.location), true)));
}
// Infer which resource a discovered id belongs to, only from supporting evidence.
export function inferResource(ident) {
  const hint = `${ident.field ?? ''} ${ident.context ?? ''}`.toLowerCase();
  const map = [['user', /user|author|profile|member|owner|account/], ['order', /order/], ['invoice', /invoice/], ['file', /file|document|doc/], ['org', /org|tenant/]];
  for (const [res, re] of map) if (re.test(hint)) return { resource: res, status: 'inferred', evidence: `field/context "${hint.trim()}"` };
  return { resource: null, status: 'unknown', evidence: null };
}
