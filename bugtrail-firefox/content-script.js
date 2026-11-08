// Classic script (no imports). Observes the rendered page of in-scope tabs, relays real fetch/XHR
// response bodies captured by page-hook.js (injected into the page's own JS world), and executes
// explicitly approved review requests (read-only GET comparisons, or an approved write request for
// a Mass Assignment test) on command from the background script only.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const emitHtml = () => {
    try { api.runtime.sendMessage({ type: 'PAGE_HTML', url: location.href, html: document.documentElement.outerHTML.slice(0, 200000) }).catch?.(() => {}); } catch { /* ignore */ }
  };
  if (document.readyState === 'complete') setTimeout(emitHtml, 300); else addEventListener('load', () => setTimeout(emitHtml, 300));

  // Inject the page-world hook via a <script src> tag (works the same way in Chrome MV3 and
  // Firefox MV2; no "world: MAIN" manifest feature required, so one code path covers both).
  try {
    const s = document.createElement('script');
    s.src = api.runtime.getURL('page-hook.js');
    s.onload = () => s.remove();
    (document.head || document.documentElement).prepend(s);
  } catch { /* ignore */ }
  addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.__bugtrail !== true || ev.data.kind !== 'network') return;
    try { api.runtime.sendMessage({ type: 'PAGE_NETWORK', url: location.href, detail: ev.data.detail }).catch?.(() => {}); } catch { /* ignore */ }
  });

  api.runtime.onMessage.addListener((m, _s, respond) => {
    if (m?.type === 'EXEC_GET') {
      (async () => {
        try {
          const u = new URL(m.url); if (u.origin !== location.origin) throw new Error('Cross-origin review blocked');
          const r = await fetch(u.toString(), { method: 'GET', credentials: 'include', redirect: 'manual', cache: 'no-store' });
          if (r.type === 'opaqueredirect') { respond({ status: null, redirectDetected: true, location: null, contentType: '', bodyAvailable: false, body: undefined, followed: false, note: 'A redirect occurred, but fetch() in manual mode does not expose the real status code, Location header or body to page scripts (the Response is "opaque"). Enable Response Inspection → Enhanced redirect inspection in Settings (Chrome only) for the real status/Location.', opaqueRedirect: true }); return; }
          const body = (await r.text()).slice(0, 200000);
          respond({ status: r.status, contentType: r.headers.get('content-type') || '', location: r.headers.get('location'), body, bodyAvailable: true, followed: false });
        } catch (e) { respond({ error: String(e.message ?? e) }); }
      })();
      return true;
    }
    if (m?.type === 'EXEC_WRITE') {
      (async () => {
        try {
          const u = new URL(m.url); if (u.origin !== location.origin) throw new Error('Cross-origin test blocked');
          if (!['POST', 'PUT', 'PATCH'].includes(m.method)) throw new Error('Only POST, PUT or PATCH are allowed here');
          const r = await fetch(u.toString(), { method: m.method, credentials: 'include', redirect: 'manual', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: m.body });
          const opaque = r.type === 'opaqueredirect'; const body = opaque ? undefined : (await r.text()).slice(0, 200000);
          respond({ status: opaque ? null : r.status, redirectDetected: opaque, contentType: r.headers.get('content-type') || '', body, bodyAvailable: body !== undefined, opaqueRedirect: opaque });
        } catch (e) { respond({ error: String(e.message ?? e) }); }
      })();
      return true;
    }
    return undefined;
  });
})();
