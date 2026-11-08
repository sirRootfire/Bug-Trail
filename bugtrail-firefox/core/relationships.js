// Ownership mapping: infer resource relationships from observed identifiers only.
// Never auto-confirms; "confirmed" is reserved for a status an operator sets explicitly elsewhere.
const OWNER_FIELD = /^(owner|user|account|created[-_]?by|author)[-_]?id$/i;
const PARENT_HINT = { order: 'user', orders: 'user', invoice: 'user', invoices: 'user', document: 'user', documents: 'user', file: 'user', files: 'user', member: 'org', members: 'org', product: 'store', products: 'store' };

export function buildRelationships(identifiers) {
  const rels = []; const byEndpoint = new Map();
  for (const id of identifiers) { const k = id.endpoint || '?'; if (!byEndpoint.has(k)) byEndpoint.set(k, []); byEndpoint.get(k).push(id); }
  // 1) Same JSON document: an owner-like field next to a resource id => observed relationship with strong evidence.
  for (const [endpoint, group] of byEndpoint) {
    const owners = group.filter((i) => OWNER_FIELD.test(i.field ?? ''));
    const resources = group.filter((i) => !OWNER_FIELD.test(i.field ?? ''));
    for (const o of owners) for (const r of resources) if (o.value !== r.value) rels.push({ id: `${o.value}->${r.value}@${endpoint}`, parentType: 'user', parentValue: o.value, childType: r.resource ?? 'resource', childValue: r.value, status: 'observed', evidence: `"${o.field}" and "${r.field ?? r.type}" co-occur in the same response at ${endpoint}`, endpoint });
  }
  // 2) Nested path segments: /users/{userId}/orders/{orderId} => parent/child structural relationship.
  const byRequest = new Map(); for (const id of identifiers) { const m = (id.endpoint || '').match(/^\/?(\w+)\/.*$/); const k = id.sources?.[0]?.requestId; if (k) { if (!byRequest.has(k)) byRequest.set(k, []); byRequest.get(k).push(id); } }
  for (const [, group] of byRequest) {
    const pathIds = group.filter((g) => /^path\[/.test(g.location)).sort((a, b) => a.location.localeCompare(b.location, undefined, { numeric: true }));
    for (let i = 0; i < pathIds.length - 1; i++) { const a = pathIds[i], b = pathIds[i + 1]; if (a.value !== b.value) rels.push({ id: `${a.value}->${b.value}@nested`, parentType: a.context || 'resource', parentValue: a.value, childType: b.context || 'resource', childValue: b.value, status: 'observed', evidence: `Nested path segments in the same URL (${a.location} → ${b.location})`, endpoint: a.endpoint }); }
  }
  // 3) Context hint (e.g. field "orders" on a user page) => weaker, inferred relationship.
  for (const id of identifiers) { const hint = PARENT_HINT[(id.context || id.field || '').toLowerCase()]; if (hint) rels.push({ id: `hint:${id.value}`, parentType: hint, parentValue: null, childType: id.resource ?? id.type, childValue: id.value, status: 'inferred', evidence: `Context "${id.context ?? id.field}" suggests a ${hint} → ${id.resource ?? id.type} relationship`, endpoint: id.endpoint }); }
  const seen = new Set();
  return rels.filter((r) => (seen.has(r.id) ? false : (seen.add(r.id), true)));
}
