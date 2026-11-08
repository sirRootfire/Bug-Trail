// Runs in the PAGE's own JS world (injected via <script src>, not an isolated content-script
// context) so it can see the real Response/Request objects the page's own code creates.
// It never changes request behavior: fetch/XHR calls proceed exactly as the page wrote them.
// It only reads bodies of same-origin responses already received by the page and forwards a
// capped, best-effort copy to the isolated content script via window.postMessage.
// Explicitly NOT done here: no header injection, no request blocking, no credential use beyond
// what the page itself already sends.
(() => {
  const TAG = '__bugtrail_net__';
  const MAX = 300000;
  const post = (detail) => { try { window.postMessage({ __bugtrail: true, kind: 'network', detail }, '*'); } catch { /* ignore */ } };
  const safeText = async (res) => { try { const t = await res.clone().text(); return t.length > MAX ? t.slice(0, MAX) : t; } catch { return undefined; } };

  const origFetch = window.fetch;
  if (origFetch && !origFetch[TAG]) {
    const wrapped = async function (input, init) {
      const res = await origFetch.call(this, input, init);
      try {
        const url = typeof input === 'string' ? input : input?.url;
        const method = (init?.method || (typeof input === 'object' && input?.method) || 'GET').toUpperCase();
        const manual = (init?.redirect || (typeof input === 'object' && input?.redirect)) === 'manual';
        const sameOrigin = (() => { try { return new URL(url, location.href).origin === location.origin; } catch { return false; } })();
        if (sameOrigin) {
          const ct = res.headers.get('content-type') || '';
          const opaque = res.type === 'opaqueredirect';
          const body = opaque ? undefined : await safeText(res);
          post({ source: 'fetch', url, method, status: opaque ? 0 : res.status, opaqueRedirect: opaque, redirectManual: Boolean(manual), contentType: ct, location: res.headers.get('location'), body, finalUrl: res.url, timestamp: Date.now() });
        }
      } catch { /* instrumentation must never break the page */ }
      return res;
    };
    wrapped[TAG] = true; window.fetch = wrapped;
  }
  const XP = XMLHttpRequest.prototype; const openOrig = XP.open; const sendOrig = XP.send;
  if (openOrig && !openOrig[TAG]) {
    XP.open = function (method, url, ...rest) { this.__bt = { method: String(method || 'GET').toUpperCase(), url }; return openOrig.call(this, method, url, ...rest); };
    XP.open[TAG] = true;
    XP.send = function (...args) {
      this.addEventListener('loadend', () => {
        try {
          const url = this.__bt?.url; const method = this.__bt?.method ?? 'GET';
          const sameOrigin = (() => { try { return new URL(url, location.href).origin === location.origin; } catch { return false; } })();
          if (!sameOrigin) return;
          let body; try { body = typeof this.responseText === 'string' ? this.responseText.slice(0, MAX) : undefined; } catch { body = undefined; }
          post({ source: 'xhr', url, method, status: this.status, contentType: this.getResponseHeader('content-type') || '', location: this.getResponseHeader('location'), body, finalUrl: this.responseURL, timestamp: Date.now() });
        } catch { /* ignore */ }
      });
      return sendOrig.apply(this, args);
    };
    XP.send[TAG] = true;
  }
})();
