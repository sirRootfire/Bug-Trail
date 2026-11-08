// Endpoint templating: /api/orders/1001 -> /api/orders/{orderId}
const SEG_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const singular = (s) => s.replace(/ies$/i, 'y').replace(/(ss)$/i, '$1').replace(/s$/i, '');
export function templatePath(pathname) {
  const parts = pathname.split('/');
  return parts.map((p, i) => {
    if (!p) return p;
    const prev = (parts[i - 1] || '').replace(/\{.*\}/, '');
    const isId = SEG_UUID.test(p) || /^\d+$/.test(p) || /^[0-9a-f]{24}$/i.test(p);
    if (!isId) return p;
    const base = prev ? singular(prev) : 'id';
    return `{${base}Id}`;
  }).join('/');
}
export function endpointKey(method, urlString) {
  try { const u = new URL(urlString); return `${method.toUpperCase()} ${u.host}${templatePath(u.pathname)}`; }
  catch { return `${method} ${urlString}`; }
}
export function buildEndpoints(requests, findings = []) {
  const map = new Map();
  for (const r of requests) {
    let u; try { u = new URL(r.url); } catch { continue; }
    const key = `${u.host}${templatePath(u.pathname)}`;
    const e = map.get(key) ?? { key, host: u.host, template: templatePath(u.pathname), methods: new Set(), statuses: new Set(), observations: 0, identifiers: new Set(), identities: new Set(), last: null, lastStatus: null, requestIds: [], findingIds: [] };
    e.methods.add(r.method); if (r.status) e.statuses.add(r.status);
    e.observations++; (r.identifiers ?? []).forEach((i) => e.identifiers.add(i.id)); if (r.identity) e.identities.add(r.identity);
    if (!e.last || r.timestamp > e.last) { e.last = r.timestamp; e.lastStatus = r.status; }
    e.requestIds.push(r.id);
    map.set(key, e);
  }
  for (const f of findings) { const e = map.get(f.endpointKey); if (e) e.findingIds.push(f.id); }
  return [...map.values()].map((e) => ({ ...e, methods: [...e.methods], statuses: [...e.statuses], identifiers: [...e.identifiers], identities: [...e.identities], reviewStatus: e.findingIds.length ? 'needs-review' : 'observed' }));
}
