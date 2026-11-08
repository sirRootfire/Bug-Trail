import { api, send } from './shared/ext.js';
const $ = (s) => document.querySelector(s);
async function refresh() {
  try {
    const { state: s, endpoints } = await send('GET_STATE');
    if (!s) throw new Error('No response from background');
    $('#d').className = `d ${s.capture.active ? 'on' : ''}`; $('#s').textContent = s.capture.active ? 'Capture active' : 'Capture stopped';
    $('#t').textContent = s.settings.scopes.length ? `Scope: ${s.settings.scopes.map((x) => x.hostname).join(', ')}` : 'No scope configured — open Workspace → Settings';
    const need = s.findings.filter((f) => ['Potential', 'Needs Verification'].includes(f.status)).length;
    $('#c').innerHTML = [[s.requests.length, 'Requests'], [endpoints.length, 'Endpoints'], [s.identifiers.length, 'Identifiers'], [need, 'To review']].map(([n, l]) => `<div><b>${n}</b>${l}</div>`).join('');
    $('#tg').textContent = s.capture.active ? 'Stop capture' : 'Start capture'; $('#e').textContent = '';
  } catch (e) { $('#e').textContent = String(e.message ?? e); }
}
$('#tg').addEventListener('click', async () => { const { state: s } = await send('GET_STATE'); const r = await send(s.capture.active ? 'STOP_CAPTURE' : 'START_CAPTURE'); if (r?.error) $('#e').textContent = r.error; refresh(); });
$('#ws').addEventListener('click', () => api.tabs.create({ url: api.runtime.getURL('app.html') }));
api.storage.onChanged.addListener(refresh); refresh();
