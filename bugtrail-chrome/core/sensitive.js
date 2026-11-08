// Contextual sensitive-data detection. Returns signals with REDACTED evidence only.
import { isPlaceholder, maskSecret } from './redact.js';

const PWD_FIELD = /pass(word|wd)?|pwd|secret/i;
const KEY_FIELD = /api[-_]?key|apikey|access[-_]?key|secret[-_]?key/i;
const TOKEN_FIELD = /(access|refresh|auth|bearer|session)[-_]?token|^token$|jwt/i;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const KEY_SHAPES = [/\bsk_(live|test)_[A-Za-z0-9]{16,}\b/, /\bAKIA[0-9A-Z]{16}\b/, /\bghp_[A-Za-z0-9]{30,}\b/, /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/];

const sig = (o) => ({ confidence: 'medium', verification: 'potential', ...o });

// <input type="password" value="..."> : real value vs placeholder vs empty
export function analyzePasswordInputs(html) {
  const out = [];
  const re = /<input\b[^>]*>/gi; let m;
  while ((m = re.exec(String(html ?? '')))) {
    const tag = m[0];
    const attr = (n) => (tag.match(new RegExp(`\\b${n}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')) || []).slice(1).find((x) => x !== undefined);
    const type = (attr('type') || '').toLowerCase(); const name = attr('name') || attr('id') || '';
    if (type !== 'password') continue;
    const hasValue = /\bvalue\s*=/i.test(tag); const value = attr('value');
    if (!hasValue || value === undefined || value === '') { out.push({ kind: 'password-input-empty', field: name, disclosed: false }); continue; }
    if (isPlaceholder(value)) { out.push({ kind: 'password-input-placeholder', field: name, disclosed: false }); continue; }
    out.push({ kind: 'password-input-value', field: name, disclosed: true, redacted: maskSecret(value), _value: value });
  }
  return out;
}
function walkJson(obj, cb, path = '', depth = 0) {
  if (depth > 8 || obj == null) return;
  if (Array.isArray(obj)) return obj.slice(0, 50).forEach((x, i) => walkJson(x, cb, `${path}[${i}]`, depth + 1));
  if (typeof obj === 'object') return Object.entries(obj).forEach(([k, v]) => walkJson(v, cb, path ? `${path}.${k}` : k, depth + 1));
  cb(path, path.split(/[.\[]/).pop().replace(/\]$/, ''), obj);
}
// Scan a body (JSON / HTML / text). `where` labels the source ("redirect-original-body", "final-body").
export function detectSensitive(body, contentType = '', where = 'response-body') {
  const text = String(body ?? ''); const signals = [];
  if (!text) return signals;
  let json = null;
  if (/json/i.test(contentType) || /^\s*[{\[]/.test(text)) { try { json = JSON.parse(text); } catch { json = null; } }
  const add = (category, field, value, extra = {}) => signals.push(sig({ category, where, field, redacted: maskSecret(value), _value: String(value), ...extra }));
  if (json) {
    walkJson(json, (path, key, val) => {
      if (typeof val !== 'string' && typeof val !== 'number') return;
      const s = String(val);
      if (PWD_FIELD.test(key) && !isPlaceholder(s)) add('password', path, s, { confidence: 'medium' });
      else if (KEY_FIELD.test(key) && !isPlaceholder(s)) add('api-key', path, s, { confidence: 'high' });
      else if (TOKEN_FIELD.test(key) && !isPlaceholder(s)) add('token', path, s, { confidence: 'high' });
      else if (/^e?-?mail$/i.test(key) && EMAIL.test(s)) add('email', path, s, { confidence: 'low' });
    });
  } else {
    for (const p of analyzePasswordInputs(text)) if (p.disclosed) add('password', `input[name=${p.field}]`, p._value, { htmlInput: 'type=password', confidence: 'high' });
    // key/value text such as "Your API key is: abc123" or api_key=abc
    const kv = /(api[-_ ]?key|access[-_ ]?token|secret[-_ ]?key)\s*(?:is|=|:)\s*["']?([A-Za-z0-9._\-]{12,})/gi; let m;
    while ((m = kv.exec(text))) if (!isPlaceholder(m[2])) add(/token/i.test(m[1]) ? 'token' : 'api-key', m[1], m[2], { confidence: 'medium' });
    for (const re of KEY_SHAPES) { const x = text.match(re); if (x) add('api-key', 'pattern-match', x[0], { confidence: 'low' }); }
  }
  const seen = new Set();
  return signals.filter((s) => { const k = `${s.category}|${s.field}|${s._value}`; if (seen.has(k)) return false; seen.add(k); return true; });
}
export const stripValues = (signals) => signals.map(({ _value, ...rest }) => rest);
