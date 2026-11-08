import { api } from './ext.js';
const KEY = 'bugtrail.v2';
export const DEFAULTS = () => ({
  settings: {
    captureBodies: false, maxRequests: 3000, maskSecrets: true, retentionDays: 14, theme: 'dark', density: 'comfortable',
    pageHookEnabled: true, enhancedInspection: false,
    autoReview: { maxPerRun: 5, maxRunsPer30m: 10, methods: ['GET'], followRedirects: false },
    scopes: [], excluded: [],
  },
  capture: { active: false, startedAt: null, activeIdentity: null, debuggingTabId: null },
  requests: [], identifiers: [], identities: [], findings: [], reviews: [], privilege: [], signals: [], audit: [], credentials: [],
});
// Retention only prunes raw capture logs (requests/signals/privilege/reviews/audit). Findings,
// identities, identifiers and credentials are curated state the tester built, not a passive log,
// so they are never pruned automatically.
function prune(s) {
  const days = Number(s.settings.retentionDays) || 0; if (!days) return s;
  const cutoff = Date.now() - days * 86400000;
  s.requests = s.requests.filter((r) => (r.timestamp ?? 0) >= cutoff);
  s.signals = s.signals.filter((r) => (r.t ?? 0) >= cutoff);
  s.privilege = s.privilege.filter((r) => (r.t ?? 0) >= cutoff);
  s.reviews = s.reviews.filter((r) => (r.t ?? 0) >= cutoff);
  s.audit = s.audit.filter((r) => (r.t ?? 0) >= cutoff);
  return s;
}
let chain = Promise.resolve();
async function read() {
  const r = await api.storage.local.get(KEY); const d = DEFAULTS(); const v = r[KEY] ?? {};
  const merged = { ...d, ...v, settings: { ...d.settings, ...(v.settings ?? {}), autoReview: { ...d.settings.autoReview, ...(v.settings?.autoReview ?? {}) } }, capture: { ...d.capture, ...(v.capture ?? {}) } };
  return prune(merged);
}
export const store = {
  read,
  update(mutator) { const op = chain.then(async () => { const cur = await read(); const next = (await mutator(cur)) ?? cur; await api.storage.local.set({ [KEY]: next }); return next; }); chain = op.catch(() => {}); return op; },
  async audit(action, detail, allowed = true) { return store.update((s) => { s.audit.unshift({ id: crypto.randomUUID(), t: Date.now(), action, detail: String(detail).slice(0, 300), allowed }); s.audit = s.audit.slice(0, 1000); }); },
  async clear() { await api.storage.local.remove(KEY); chain = Promise.resolve(); await api.storage.local.set({ [KEY]: DEFAULTS() }); },
};
