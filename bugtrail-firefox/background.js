import { api } from './shared/ext.js';
import { store } from './shared/store.js';
import { isInScope, normalizeHost } from './core/scope.js';
import { sanitizeHeaders, sanitizeUrl, maskId, maskSecret } from './core/redact.js';
import { fromUrl, fromJson, fromGraphql, fromForm, fromHtml, inferResource } from './core/identifiers.js';
import { detectSensitive, stripValues } from './core/sensitive.js';
import { observePrivilege, isAdminPath, isPrivField } from './core/privilege.js';
import { evaluateComparison, evaluateMassAssignment, evaluatePrivilegeReview, STATUSES } from './core/findings.js';
import { toJson, toMarkdown } from './core/report.js';
import { buildEndpoints } from './core/endpoints.js';
import { buildRelationships } from './core/relationships.js';
import { parseCredentials } from './core/credentials.js';
import * as debuggerCapture from './debugger-capture.js';

// Live "Debugging active" indicator: as soon as chrome.debugger actually attaches/detaches for an
// Enhanced-inspection capture, reflect it in storage so every open workspace/popup updates near-
// instantly via storage.onChanged — not just "the setting is on", but "it is attached right now".
debuggerCapture.setActivityHandler((tabId, active) => { void store.update((s) => { s.capture.debuggingTabId = active ? tabId : (s.capture.debuggingTabId === tabId ? null : s.capture.debuggingTabId); }); });

const starts = new Map(); const reqBodies = new Map();
const LIMITS = { bodyBytes: 64000 };
const decode = (raw) => (raw ?? []).map((p) => (p.bytes ? new TextDecoder().decode(p.bytes) : '')).join('').slice(0, LIMITS.bodyBytes);
const WEB = { urls: ['http://*/*', 'https://*/*'] };
const live = (s, url) => s.capture.active && isInScope(url, s.settings.scopes, s.settings.excluded);

function mergeIdentifiers(s, found, requestId) {
  for (const f of found) {
    const ex = s.identifiers.find((i) => i.id === f.id);
    const res = inferResource(f);
    if (ex) { ex.seen = (ex.seen ?? 1) + 1; if (!ex.sources.some((x) => x.requestId === requestId && x.location === f.location)) ex.sources.push({ requestId, endpoint: f.endpoint, location: f.location, method: f.discoveryMethod, context: f.context, identity: f.identity, t: f.timestamp }); }
    else s.identifiers.unshift({ ...f, seen: 1, resource: res.resource, relationship: res.status, relationshipEvidence: res.evidence, sources: [{ requestId, endpoint: f.endpoint, location: f.location, method: f.discoveryMethod, context: f.context, identity: f.identity, t: f.timestamp }] });
  }
  s.identifiers = s.identifiers.slice(0, 3000);
}
function recordPrivilege(s, obs) { for (const o of obs) { if (!s.privilege.some((p) => p.requestId === o.requestId && p.field === o.field)) s.privilege.unshift({ id: crypto.randomUUID(), t: Date.now(), ...o }); } s.privilege = s.privilege.slice(0, 500); }

// ---------- Passive capture: navigation/XHR-level metadata (webRequest; no bodies) ----------
api.webRequest.onBeforeRequest.addListener((d) => {
  starts.set(d.requestId, Date.now());
  const raw = d.requestBody?.raw; if (raw) reqBodies.set(d.requestId, decode(raw)); else if (d.requestBody?.formData) reqBodies.set(d.requestId, new URLSearchParams(Object.entries(d.requestBody.formData).flatMap(([k, v]) => v.map((x) => [k, x]))).toString());
}, WEB, ['requestBody']);

async function recordDone(d, redirectTo) {
  const s0 = await store.read(); if (!live(s0, d.url)) { starts.delete(d.requestId); reqBodies.delete(d.requestId); return; }
  const t0 = starts.get(d.requestId); starts.delete(d.requestId); const body = reqBodies.get(d.requestId); reqBodies.delete(d.requestId);
  const hdr = (n) => d.responseHeaders?.find((h) => h.name.toLowerCase() === n)?.value;
  const ct = (d.requestHeaders?.find((h) => h.name.toLowerCase() === 'content-type')?.value) ?? '';
  const ident = s0.capture.activeIdentity; let u; try { u = new URL(d.url); } catch { return; }
  const ctx = { endpoint: u.pathname, identity: ident, ts: Date.now() };
  let found = fromUrl(d.url, ctx);
  if (body) { let j = null; try { j = JSON.parse(body); } catch { /* not json */ }
    if (j && (j.query || j.variables)) found.push(...fromGraphql(j, ctx)); else if (j) found.push(...fromJson(j, ctx, 'json-body')); else if (/x-www-form-urlencoded/i.test(ct) || /=/.test(body)) found.push(...fromForm(body, ctx)); }
  const id = crypto.randomUUID();
  const priv = body ? observePrivilege({ method: d.method, url: d.url, requestBody: body, responseBody: null, identity: ident, requestId: id }) : [];
  const status = d.statusCode;
  const isRedirect = [301, 302, 303, 307, 308].includes(status);
  const rec = { id, tabId: d.tabId, method: d.method, url: sanitizeUrl(d.url), host: u.host, path: u.pathname, status, contentType: hdr('content-type') ?? null, durationMs: t0 ? Date.now() - t0 : null, timestamp: Date.now(), type: d.type, identity: ident, queryKeys: [...u.searchParams.keys()], bodyKeys: body ? (() => { try { return Object.keys(JSON.parse(body)).slice(0, 30); } catch { return []; } })() : [], responseHeaders: sanitizeHeaders(d.responseHeaders), bodyInspected: false, redirect: isRedirect ? { originalStatus: status, location: hdr('location') ?? null, originalBodyAvailable: false, inspectionStatus: 'webRequest metadata only — body not read at this stage (see page-hook / enhanced inspection)', followedBy: redirectTo ?? null } : null, identifiers: found.map((f) => ({ id: f.id, field: f.field, location: f.location, confidence: f.confidence })), admin: isAdminPath(u.pathname) };
  await store.update((s) => { if (!s.capture.active) return; s.requests.unshift(rec); s.requests = s.requests.slice(0, s.settings.maxRequests); mergeIdentifiers(s, found, id); recordPrivilege(s, priv); });
}
api.webRequest.onCompleted.addListener((d) => { void recordDone(d); }, WEB, ['responseHeaders']);
api.webRequest.onBeforeRedirect.addListener((d) => { void recordDone({ ...d, statusCode: d.statusCode }, d.redirectUrl); }, WEB, ['responseHeaders']);
api.webRequest.onErrorOccurred.addListener((d) => { starts.delete(d.requestId); reqBodies.delete(d.requestId); }, WEB);

// ---------- Passive body capture: real fetch()/XHR response bodies from the PAGE's own JS world.
// Relayed by content-script.js from page-hook.js (see that file for exactly what it reads and why
// this does not change request behavior). This is what makes passive Sensitive Data Exposure,
// response-side Mass Assignment observation and response-JSON identifier discovery possible
// without any extra permission, in both Chrome and Firefox. It cannot see an original 3xx body —
// no in-page API exposes that; see Settings → Response Inspection for the Chrome-only alternative.
async function handlePageNetwork(detail, tabUrl) {
  const s0 = await store.read(); if (!s0.settings.pageHookEnabled || !live(s0, tabUrl) || !isInScope(detail.url, s0.settings.scopes, s0.settings.excluded)) return;
  let u; try { u = new URL(detail.url, tabUrl); } catch { return; }
  const ident = s0.capture.activeIdentity;
  const sig = detail.body ? detectSensitive(detail.body, detail.contentType, 'passive-fetch-body') : [];
  let ids = [];
  if (detail.body) { try { const j = JSON.parse(detail.body); ids = fromJson(j, { endpoint: u.pathname, identity: ident, ts: Date.now() }, 'response-json'); } catch { /* not json */ } }
  const priv = observePrivilege({ method: detail.method, url: detail.url, requestBody: null, responseBody: detail.body ?? null, identity: ident, requestId: `net:${detail.url}:${detail.timestamp}` });
  if (!sig.length && !ids.length && !priv.length && !detail.opaqueRedirect) return;
  await store.update((st) => {
    const match = st.requests.find((r) => r.url.split('?')[0] === u.origin + u.pathname && r.method === detail.method && Math.abs((r.timestamp ?? 0) - (detail.timestamp ?? Date.now())) < 15000);
    if (match) { match.bodyInspected = true; if (detail.opaqueRedirect && match.redirect) match.redirect.inspectionStatus = 'opaque to in-page fetch() (redirect:manual); browser withholds status/body from page scripts — see enhanced inspection'; }
    mergeIdentifiers(st, ids, match?.id ?? 'page-network');
    recordPrivilege(st, priv);
    for (const g of stripValues(sig)) if (!st.signals.some((x) => x.endpoint === u.pathname && x.field === g.field && x.category === g.category && x.redacted === g.redacted)) st.signals.unshift({ id: crypto.randomUUID(), t: Date.now(), endpoint: u.pathname, identity: ident, source: 'passive-fetch-body', ...g });
    st.signals = st.signals.slice(0, 500);
  });
}

// ---------- Review (Auto Review): preview -> explicit approval -> bounded GET comparisons ----------
function replaceId(urlString, ident, newValue) {
  const u = new URL(urlString);
  if (ident.location.startsWith('query.')) { const k = ident.location.slice(6); if (!u.searchParams.has(k)) return null; u.searchParams.set(k, newValue); return u.toString(); }
  const m = ident.location.match(/^path\[(\d+)\]$/); if (m) { const parts = u.pathname.split('/').filter(Boolean); parts[+m[1]] = encodeURIComponent(newValue); u.pathname = '/' + parts.join('/'); return u.toString(); }
  return null;
}
function buildPlan(s, requestId, newIds) {
  const req = s.requests.find((r) => r.id === requestId); if (!req) throw new Error('Request not found');
  if (req.method !== 'GET') throw new Error('Only GET requests are allowed in Auto Review');
  const ident = s.identifiers.find((i) => req.identifiers.some((x) => x.id === i.id) && (i.location.startsWith('query.') || /^path\[/.test(i.location)));
  if (!ident) throw new Error('This request has no URL-based identifier to compare');
  const ar = s.settings.autoReview; const observed = new Map(s.identifiers.map((i) => [i.value, i]));
  const limit = Math.min(ar.maxPerRun, 5); const unique = [...new Set(newIds)].filter((v) => v !== ident.value);
  if (!unique.length) throw new Error('Select at least one observed identifier different from the original');
  if (unique.length > limit) throw new Error(`Maximum ${limit} comparisons per run`);
  const cmp = unique.map((v) => { const o = observed.get(v); if (!o) throw new Error('Identifier was not observed in this testing session (no guessing/enumeration)'); const url = replaceId(req.url.replace(/\[redacted\]/g, 'x'), ident, v) ?? replaceId(req.url, ident, v); if (!url) throw new Error('Could not substitute identifier in URL'); return { newValue: v, url, identity: s.identities.find((x) => x.label === v)?.label ?? null, ownerEvidence: s.identities.some((x) => x.label === v) ? 'configured identity' : 'none (owner not established)', scope: isInScope(url, s.settings.scopes, s.settings.excluded) }; });
  const runs = s.reviews.filter((r) => r.t > Date.now() - 30 * 60000).length;
  return { requestId, method: 'GET', endpoint: req.path, host: req.host, original: { value: ident.value, masked: ident.masked, identity: req.identity ?? null, location: ident.location, url: req.url }, comparisons: cmp, count: cmp.length, runsInWindow: runs, maxRuns: ar.maxRunsPer30m, allInScope: cmp.every((c) => c.scope) && isInScope(req.url, s.settings.scopes, s.settings.excluded), expected: 'Server should deny or return no data for identifiers owned by another identity.', impact: 'Read-only GET requests using the current tab session. No state is changed.', ident };
}
async function execInTab(tabId, url, s) {
  if (s?.settings?.enhancedInspection && debuggerCapture.available()) {
    // CDP must be listening BEFORE the request is sent, or there is nothing to intercept — so the
    // debugger attaches first and the content-script fetch is the `trigger` fired once it's armed.
    try {
      const { triggerResult: r, captured } = await debuggerCapture.captureWithTrigger(tabId, url, () => api.tabs.sendMessage(tabId, { type: 'EXEC_GET', url }));
      if (!r || r.error) throw new Error(r?.error ?? 'Content script unavailable — reload the target tab');
      if (r.opaqueRedirect && captured) return { ...r, status: captured.status, location: captured.location, contentType: captured.contentType || r.contentType, enhanced: true, capturedVia: captured.capturedVia, note: `${r.note} Status/Location recovered via chrome.debugger.` };
      if (r.opaqueRedirect) return { ...r, enhancedError: 'No matching response observed via chrome.debugger within the timeout' };
      return r;
    } catch (e) {
      // Fail open to the ordinary (honest, non-enhanced) path rather than failing the whole review.
      const r = await api.tabs.sendMessage(tabId, { type: 'EXEC_GET', url });
      if (!r || r.error) throw new Error(r?.error ?? 'Content script unavailable — reload the target tab');
      return { ...r, enhancedError: String(e.message ?? e) };
    }
  }
  const r = await api.tabs.sendMessage(tabId, { type: 'EXEC_GET', url });
  if (!r || r.error) throw new Error(r?.error ?? 'Content script unavailable — reload the target tab');
  return r;
}
async function runReview(msg) {
  const s = await store.read();
  if (!msg.approved) throw new Error('Explicit approval required');
  const plan = buildPlan(s, msg.requestId, msg.newIds);
  const runs = s.reviews.filter((r) => r.t > Date.now() - 30 * 60000).length;
  if (runs >= plan.maxRuns) throw new Error(`Review limit reached (${plan.maxRuns} runs per 30 minutes)`);
  if (!plan.allInScope) { await store.audit('review-blocked-out-of-scope', `${plan.endpoint}`, false); throw new Error('Blocked: URL outside configured scope (no request was sent)'); }
  const tabId = Number(msg.tabId); if (!Number.isInteger(tabId) || tabId < 0) throw new Error('Open the target page in a tab first');
  await store.audit('review-run-approved', `GET ${plan.endpoint} x${plan.count}`);
  const base = await execInTab(tabId, plan.original.url.replace('%5Bredacted%5D', 'x'), s);
  const results = []; let fiveXX = 0;
  for (const c of plan.comparisons) {
    const s2 = await store.read(); if (!isInScope(c.url, s2.settings.scopes, s2.settings.excluded)) { await store.audit('review-blocked-out-of-scope', c.url, false); continue; }
    await store.audit('review-request', `GET ${new URL(c.url).pathname}${new URL(c.url).search ? '?…' : ''}`);
    let mod; try { mod = await execInTab(tabId, c.url, s2); } catch (e) { results.push({ newValue: c.newValue, error: String(e.message ?? e) }); continue; }
    if (mod.status >= 500) fiveXX++; if (mod.status === 429 || fiveXX >= 2) { await store.audit('review-stopped', `rate limit / repeated 5xx (${mod.status})`, false); break; }
    const ev = evaluateComparison({ baseline: base, modified: mod, baseId: plan.original.value, modId: c.newValue, endpoint: plan.endpoint, method: 'GET', sourceIdentity: plan.original.identity, targetIdentity: c.identity, requestRefs: { baselineRequestId: msg.requestId, comparisonUrl: sanitizeUrl(c.url) } });
    results.push({ newValue: c.newValue, maskedNew: maskId(c.newValue), status: mod.status, enhanced: Boolean(mod.enhanced), ...ev, findings: ev.findings.map((f) => f.id) });
    await store.update((st) => { for (const f of ev.findings) { f.endpointKey = `${plan.host}${plan.endpoint}`; st.findings.unshift(f); } for (const sg of ev.newSignals) st.signals.unshift({ id: crypto.randomUUID(), t: Date.now(), endpoint: plan.endpoint, identity: c.identity ?? null, ...sg }); st.signals = st.signals.slice(0, 500); });
    await new Promise((r) => setTimeout(r, 350));
  }
  await store.update((st) => { st.reviews.unshift({ id: crypto.randomUUID(), t: Date.now(), requestId: msg.requestId, endpoint: plan.endpoint, count: results.length, results: results.map((r) => ({ newValue: r.maskedNew, status: r.status, enhanced: r.enhanced, changes: r.diff?.changes?.length ?? 0, findings: r.findings, redirect: r.redirect, notes: r.notes, error: r.error })) }); st.reviews = st.reviews.slice(0, 100); });
  return { ok: true, results, baselineStatus: base.status, baselineEnhanced: Boolean(base.enhanced) };
}

// ---------- Mass Assignment Review: dedicated, explicit-approval, test-account-only workflow ----------
function assertTestIdentity(s, identityId) {
  const idn = s.identities.find((i) => i.id === identityId);
  if (!idn) throw new Error('Select a configured identity');
  if (!idn.isTestAccount) throw new Error('Mass Assignment tests require an identity explicitly marked "dedicated test account" in Identities');
  return idn;
}
function parseJsonField(text, label) { try { return text?.trim() ? JSON.parse(text) : {}; } catch { throw new Error(`${label} is not valid JSON`); } }
function previewMassAssignment(s, m) {
  const url = String(m.url || ''); let u; try { u = new URL(url); } catch { throw new Error('A valid absolute URL is required (pick a captured POST/PUT/PATCH request)'); }
  if (!['POST', 'PUT', 'PATCH'].includes(String(m.method).toUpperCase())) throw new Error('Mass Assignment tests only use POST, PUT or PATCH');
  const base = parseJsonField(m.baseBodyText, 'Base request body'); const field = String(m.field || '').trim(); if (!field) throw new Error('Field name is required');
  // The field's value is typed on a text input, so a numeric/boolean-looking value is coerced the
  // way a JSON body would hold it (many servers type-check strictly and would silently ignore a
  // string "9" sent for a numeric field) — the coerced value actually sent is always shown below.
  const raw = m.value; let value = raw;
  if (/^-?\d+(\.\d+)?$/.test(String(raw ?? '').trim())) value = Number(raw);
  else if (/^(true|false)$/i.test(String(raw ?? '').trim())) value = String(raw).toLowerCase() === 'true';
  const modified = { ...base, [field]: value };
  const idn = assertTestIdentity(s, m.identityId);
  return { url, method: String(m.method).toUpperCase(), endpoint: u.pathname, field, originalValue: base[field] ?? null, submittedValue: value, submittedRaw: raw, baseBody: base, modifiedBody: modified, identity: idn.label, inScope: isInScope(url, s.settings.scopes, s.settings.excluded), flaggedPrivilegeField: isPrivField(field) };
}
async function runMassAssignment(m) {
  const s = await store.read(); if (!m.approved) throw new Error('Explicit approval is required');
  const plan = previewMassAssignment(s, m);
  if (!plan.inScope) { await store.audit('mass-assignment-blocked-out-of-scope', plan.endpoint, false); throw new Error('Blocked: endpoint is outside the configured scope'); }
  const tabId = Number(m.tabId); if (!Number.isInteger(tabId) || tabId < 0) throw new Error('Open the target page (signed in as the test account) in a tab first');
  await store.audit('mass-assignment-write', `${plan.method} ${plan.endpoint} +${plan.field} (test account: ${plan.identity})`);
  const r = await api.tabs.sendMessage(tabId, { type: 'EXEC_WRITE', url: plan.url, method: plan.method, body: JSON.stringify(plan.modifiedBody) });
  if (!r || r.error) throw new Error(r?.error ?? 'Content script unavailable — reload the target tab');
  let parsed = null; try { parsed = r.body ? JSON.parse(r.body) : null; } catch { /* non-JSON response */ }
  const responseValue = parsed && typeof parsed === 'object' ? parsed[plan.field] : null;
  const accepted = r.status >= 200 && r.status < 300;
  const finding = evaluateMassAssignment({ endpoint: plan.endpoint, method: plan.method, identity: plan.identity, field: plan.field, submittedValue: plan.submittedValue, originalValue: plan.originalValue, responseValue, accepted, persisted: false });
  await store.update((st) => { st.findings.unshift(finding); });
  await store.audit('mass-assignment-result', `${plan.method} ${plan.endpoint} → ${r.status}${accepted ? ' (accepted)' : ''}`);
  return { status: r.status, accepted, responseValueRedacted: responseValue != null && /password|secret|token/i.test(plan.field) ? maskSecret(String(responseValue)) : responseValue, findingId: finding.id };
}
async function verifyMassAssignmentPersistence(m) {
  const s = await store.read(); const f = s.findings.find((x) => x.id === m.findingId); if (!f || f.category !== 'Mass Assignment') throw new Error('Finding not found');
  if (!isInScope(m.verifyUrl, s.settings.scopes, s.settings.excluded)) throw new Error('Verification URL is outside the configured scope');
  const tabId = Number(m.tabId); if (!Number.isInteger(tabId) || tabId < 0) throw new Error('Open the target page in a tab first');
  const r = await api.tabs.sendMessage(tabId, { type: 'EXEC_GET', url: m.verifyUrl });
  if (!r || r.error) throw new Error(r?.error ?? 'Content script unavailable');
  let parsed = null; try { parsed = r.body ? JSON.parse(r.body) : null; } catch { /* ignore */ }
  const current = parsed && typeof parsed === 'object' ? parsed[f.evidence.addedProperty] : null;
  const persisted = String(current) === String(f.evidence.submittedValue);
  const updated = evaluateMassAssignment({ endpoint: f.endpoint, method: f.method, identity: f.sourceIdentity, field: f.evidence.addedProperty, submittedValue: f.evidence.submittedValue, originalValue: f.evidence.originalValue, responseValue: f.evidence.responseValue, accepted: f.evidence.serverAccepted, persisted });
  await store.update((st) => { const idx = st.findings.findIndex((x) => x.id === m.findingId); if (idx >= 0) st.findings[idx] = { ...updated, id: f.id, createdAt: f.createdAt }; });
  await store.audit('mass-assignment-persistence-check', `${f.endpoint} ${f.evidence.addedProperty} persisted=${persisted}`);
  return { persisted, currentValueRedacted: current };
}

// ---------- Privilege Escalation Review: same URL from N authenticated tabs at once ----------
// "vertical": participants are ordered low -> high privilege; only CONSECUTIVE pairs are compared
//   (regular vs admin, admin vs super-admin, ...) — comparing a non-adjacent pair would assume an
//   ordering relationship the tester never actually asserted.
// "horizontal": participants are nominally equal rank, different accounts; EVERY pair is compared,
//   since any difference between same-rank accounts is potentially meaningful regardless of order.
function pairsFor(kind, participants) {
  if (kind === 'vertical') return participants.slice(0, -1).map((p, i) => [p, participants[i + 1]]);
  const pairs = []; for (let i = 0; i < participants.length; i++) for (let j = i + 1; j < participants.length; j++) pairs.push([participants[i], participants[j]]);
  return pairs;
}
async function runPrivilegeReview(m) {
  const s = await store.read(); if (!m.approved) throw new Error('Explicit approval is required');
  const url = String(m.url || ''); let parsedUrl; try { parsedUrl = new URL(url); } catch { throw new Error('A valid absolute URL is required'); }
  if (!isInScope(url, s.settings.scopes, s.settings.excluded)) { await store.audit('privilege-review-blocked-out-of-scope', parsedUrl.pathname, false); throw new Error('Blocked: URL is outside the configured scope'); }
  const participants = (Array.isArray(m.participants) ? m.participants : []).map((p, i) => ({ label: String(p.label || '').trim() || `Identity ${i + 1}`, tabId: Number(p.tabId) })).filter((p) => Number.isInteger(p.tabId));
  if (participants.length < 2) throw new Error('Select an open, in-scope tab for at least two identities');
  if (participants.length > 5) throw new Error('Maximum 5 identities per run');
  if (new Set(participants.map((p) => p.tabId)).size !== participants.length) throw new Error('Choose a different tab for each identity (one authenticated session per identity)');
  const kind = m.kind === 'vertical' ? 'vertical' : 'horizontal';
  const pairs = pairsFor(kind, participants);
  await store.audit('privilege-review-run', `${kind} GET ${parsedUrl.pathname} across ${participants.length} identities (${participants.map((p) => p.label).join(', ')})`);
  // Each tab's response is fetched exactly once, even if it takes part in several pairs.
  const responses = new Map();
  await Promise.all(participants.map(async (p) => { responses.set(p.tabId, await execInTab(p.tabId, url, s)); }));
  const results = [];
  for (const [low, high] of pairs) {
    const lowResponse = responses.get(low.tabId), highResponse = responses.get(high.tabId);
    const finding = evaluatePrivilegeReview({ endpoint: parsedUrl.pathname, method: 'GET', kind, lowIdentity: low.label, highIdentity: high.label, lowResponse, highResponse, requestRefs: { url: sanitizeUrl(url) } });
    await store.update((st) => { st.findings.unshift(finding); for (const sg of finding.sensitiveSignals ?? []) st.signals.unshift({ id: crypto.randomUUID(), t: Date.now(), endpoint: parsedUrl.pathname, identity: high.label, ...sg }); });
    results.push({ lowIdentity: low.label, highIdentity: high.label, lowStatus: lowResponse.status, highStatus: highResponse.status, findingId: finding.id, finding });
  }
  return { participants: participants.map((p) => ({ label: p.label, status: responses.get(p.tabId)?.status })), results };
}

// ---------- message API ----------
const publicState = (s) => ({ ...s, requests: s.requests.slice(0, 2000) });
const handlers = {
  GET_STATE: async () => { const s = await store.read(); return { state: publicState(s), endpoints: buildEndpoints(s.requests, s.findings), relationships: buildRelationships(s.identifiers), debuggerAvailable: debuggerCapture.available() }; },
  SET_SETTINGS: async (m) => { await store.update((s) => { s.settings = { ...s.settings, ...m.patch, autoReview: { ...s.settings.autoReview, ...(m.patch.autoReview ?? {}) } }; s.settings.autoReview.maxPerRun = Math.min(5, s.settings.autoReview.maxPerRun); s.settings.autoReview.methods = ['GET']; if (m.patch.enhancedInspection && !debuggerCapture.available()) s.settings.enhancedInspection = false; }); return { ok: true }; },
  SAVE_SCOPE: async (m) => { const rules = (m.scopes ?? []).map((r) => ({ hostname: normalizeHost(r.hostname), includeSubdomains: !!r.includeSubdomains, enabled: r.enabled !== false })).filter((r) => r.hostname); await store.update((s) => { s.settings.scopes = rules; s.settings.excluded = (m.excluded ?? []).map((r) => ({ hostname: normalizeHost(r.hostname), includeSubdomains: !!r.includeSubdomains, enabled: true })).filter((r) => r.hostname); }); await store.audit('scope-updated', rules.map((r) => r.hostname).join(',')); return { ok: true }; },
  START_CAPTURE: async () => { const s = await store.read(); if (!s.settings.scopes.some((r) => r.enabled)) throw new Error('Define an in-scope host first'); await store.update((x) => { x.capture.active = true; x.capture.startedAt = Date.now(); }); await store.audit('capture-start', 'user'); return { ok: true }; },
  STOP_CAPTURE: async () => { await store.update((x) => { x.capture.active = false; }); await store.audit('capture-stop', 'user'); return { ok: true }; },
  CLEAR_DATA: async () => { await store.clear(); return { ok: true }; },
  SET_ACTIVE_IDENTITY: async (m) => { await store.update((s) => { s.capture.activeIdentity = m.label || null; }); return { ok: true }; },
  SAVE_IDENTITY: async (m) => { const i = m.identity; if (!i?.label?.trim()) throw new Error('Label is required'); await store.update((s) => { const ex = s.identities.find((x) => x.id === i.id); const rec = { id: i.id ?? crypto.randomUUID(), label: i.label.trim(), role: i.role ?? '', notes: i.notes ?? '', verification: i.verification ?? 'unverified', scopeHost: i.scopeHost ?? '', isTestAccount: Boolean(i.isTestAccount) }; if (ex) Object.assign(ex, rec); else s.identities.push(rec); }); return { ok: true }; },
  DELETE_IDENTITY: async (m) => { await store.update((s) => { s.identities = s.identities.filter((i) => i.id !== m.id); }); return { ok: true }; },
  REVIEW_PREVIEW: async (m) => { const s = await store.read(); const { ident, ...plan } = buildPlan(s, m.requestId, m.newIds ?? []); return plan; },
  REVIEW_RUN: async (m) => runReview(m),
  MASS_ASSIGN_PREVIEW: async (m) => { const s = await store.read(); return previewMassAssignment(s, m); },
  MASS_ASSIGN_RUN: async (m) => runMassAssignment(m),
  MASS_ASSIGN_VERIFY: async (m) => verifyMassAssignmentPersistence(m),
  PRIV_REVIEW_RUN: async (m) => runPrivilegeReview(m),
  UPDATE_FINDING: async (m) => { if (!STATUSES.includes(m.status)) throw new Error('Invalid status'); await store.update((s) => { const f = s.findings.find((x) => x.id === m.id); if (f) { f.status = m.status; f.updatedAt = Date.now(); } }); await store.audit('finding-status', `${m.id}→${m.status}`); return { ok: true }; },
  RECORD_MASS_ASSIGNMENT: async (m) => { const f = evaluateMassAssignment({ endpoint: m.endpoint, method: m.method, identity: m.identity, field: m.field, submittedValue: m.submittedValue, originalValue: m.originalValue, responseValue: m.responseValue, accepted: !!m.accepted, persisted: !!m.persisted }); await store.update((s) => { s.findings.unshift(f); }); await store.audit('mass-assignment-recorded', `${m.method} ${m.endpoint} ${m.field}`); return { ok: true, finding: f }; },
  EXPORT: async (m) => { const s = await store.read(); const list = s.findings.filter((f) => !m.ids?.length || m.ids.includes(f.id)); const meta = { target: s.settings.scopes.map((x) => x.hostname).join(', ') }; return { text: m.format === 'json' ? toJson(list, meta) : toMarkdown(list, meta), count: list.length }; },
  IMPORT_CREDENTIALS: async (m) => { const r = parseCredentials(m.text, m.filename); if (m.commit) await store.update((s) => { for (const row of r.valid) if (!s.credentials.some((c) => c.username === row.username)) s.credentials.push({ id: crypto.randomUUID(), label: row.label, username: row.username, hasPassword: row.hasPassword }); }); return { rows: r.rows, valid: r.valid.length, invalid: r.invalid.length, duplicates: r.duplicates.length, preview: r.preview }; },
  DELETE_CREDENTIAL: async (m) => { await store.update((s) => { s.credentials = s.credentials.filter((c) => c.id !== m.id); }); return { ok: true }; },
  PAGE_HTML: async (m, sender) => {
    const s = await store.read(); const url = sender?.tab?.url ?? m.url; if (!live(s, url)) return { ok: false };
    const u = new URL(url); const ctx = { endpoint: u.pathname, identity: s.capture.activeIdentity, ts: Date.now() };
    const ids = fromHtml(m.html, ctx).concat(m.json ? fromJson(m.json, ctx, 'embedded-json') : []);
    const sig = detectSensitive(m.html, 'text/html', 'final-page-dom');
    const id = crypto.randomUUID(); const priv = [];
    await store.update((st) => { mergeIdentifiers(st, ids, id); for (const g of stripValues(sig)) if (!st.signals.some((x) => x.endpoint === u.pathname && x.field === g.field && x.category === g.category)) st.signals.unshift({ id: crypto.randomUUID(), t: Date.now(), endpoint: u.pathname, identity: ctx.identity, ...g }); st.signals = st.signals.slice(0, 500); recordPrivilege(st, priv); });
    return { ok: true, identifiers: ids.length, signals: sig.length };
  },
  PAGE_NETWORK: async (m, sender) => { await handlePageNetwork(m.detail, sender?.tab?.url ?? m.url); return { ok: true }; },
};
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== api.runtime.id) return false;
  const h = handlers[msg?.type]; if (!h) return false;
  const fromContentScript = msg.type === 'PAGE_HTML' || msg.type === 'PAGE_NETWORK';
  if (!fromContentScript && sender.tab && !sender.url?.startsWith(api.runtime.getURL(''))) { sendResponse({ error: 'Not allowed from web content' }); return false; }
  h(msg, sender).then(sendResponse).catch((e) => sendResponse({ error: String(e.message ?? e) }));
  return true;
});
