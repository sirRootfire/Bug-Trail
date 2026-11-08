// Chrome-only (chrome.debugger / CDP). Used ONLY for an explicitly approved Review action on a
// single tab the tester already has open, never for background passive capture. Attaching shows
// Chrome's own "BugTrail started debugging this browser" infobar — an unavoidable, user-visible
// signal that cannot be hidden; this module does not try to.
//
// Technique: Fetch.enable(requestStage:'Response') pauses the ORIGINAL response (including a 3xx,
// before the browser follows it) long enough to read its real status code and headers via the
// Fetch.requestPaused event, then Fetch.continueRequest lets the browser proceed normally.
// IMPORTANT: the listener must be armed BEFORE the request is sent, or there is nothing to catch —
// this module takes a `trigger` callback and fires it only once CDP is already listening.
//
// TESTED LIMIT (see evidence/CDP-REDIRECT-BODY-FINDING.md — four independent experiments against
// a local fixture server): Fetch.getResponseBody on a paused 3xx reliably FAILS with "Can only get
// response body on requests captured after headers received." Chrome's network stack never
// buffers a redirect's body because it does not need to in order to follow Location. So this
// module returns the real status/Location for a redirect (an improvement over the opaque result
// page scripts get) but never claims to read the body — it does not even try.
import { api } from './shared/ext.js';

export const available = () => typeof api.debugger === 'object';

// Lets background.js surface a LIVE "debugging active" indicator in the UI while chrome.debugger
// is actually attached (not just "the permission is granted") — called once on attach, once on
// detach, so the workspace can show the real Chrome infobar state instead of a static setting.
let activityHandler = null;
export function setActivityHandler(fn) { activityHandler = fn; }
// Safety net: if the user dismisses Chrome's "stop debugging" banner themselves, Chrome detaches
// us without our finally block running — make sure the indicator still clears.
if (available()) api.debugger.onDetach.addListener((source) => { if (source.tabId != null) activityHandler?.(source.tabId, false); });

// Attaches, arms a listener for `url` on `tabId`, calls `trigger()`, and resolves once BOTH the
// trigger's own result and (if any) a matching CDP capture are in. `captured` is null if no
// request to that exact URL was observed within the timeout (e.g. enhancedInspection raced a
// request that never fired, or the content script's request used a different tab).
export async function captureWithTrigger(tabId, url, trigger, { timeoutMs = 8000 } = {}) {
  if (!available()) throw new Error('chrome.debugger is not available (Chrome only; requires the debugger permission to be granted)');
  const target = { tabId };
  await api.debugger.attach(target, '1.3');
  activityHandler?.(tabId, true);
  try {
    await api.debugger.sendCommand(target, 'Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Response' }] });
    let settled = false;
    const capture = new Promise((resolve) => {
      const onEvent = (src, method, params) => {
        if (src.tabId !== tabId || method !== 'Fetch.requestPaused') return;
        if (params.request.url !== url || settled) { api.debugger.sendCommand(target, 'Fetch.continueRequest', { requestId: params.requestId }).catch(() => {}); return; }
        settled = true; clearTimeout(timer); api.debugger.onEvent.removeListener(onEvent);
        const status = params.responseStatusCode ?? 0;
        const headers = Object.fromEntries((params.responseHeaders ?? []).map((h) => [h.name.toLowerCase(), h.value]));
        api.debugger.sendCommand(target, 'Fetch.continueRequest', { requestId: params.requestId }).catch(() => {});
        resolve({ status, location: headers['location'] || null, contentType: headers['content-type'] || '', capturedVia: 'chrome.debugger (CDP Fetch domain) — status/headers only; body is never attempted for a redirect (tested limit)' });
      };
      const timer = setTimeout(() => { if (!settled) { settled = true; api.debugger.onEvent.removeListener(onEvent); resolve(null); } }, timeoutMs);
      api.debugger.onEvent.addListener(onEvent);
    });
    const triggerResult = await trigger();
    const captured = await capture;
    return { triggerResult, captured };
  } finally { try { await api.debugger.detach(target); } catch { /* already detached */ } activityHandler?.(tabId, false); }
}
