import { SENSITIVE_KEY } from './redact.js';
const scrub = (v) => JSON.parse(JSON.stringify(v, (k, val) => (k === '_value' ? undefined : (SENSITIVE_KEY.test(k) && typeof val === 'string' && !/^(redacted|field|category)/.test(k) && k !== 'passwordField' ? val : val))));
export function toJson(findings, meta = {}) { return JSON.stringify({ tool: 'BugTrail', generatedAt: new Date().toISOString(), note: 'Secrets are redacted. Potential findings are unverified.', ...meta, findings: scrub(findings) }, null, 2); }
export function toMarkdown(findings, meta = {}) {
  const L = [`# BugTrail Report`, '', `Generated: ${new Date().toISOString()}`, meta.target ? `Target: ${meta.target}` : '', '', '> Secrets are redacted. **Potential** findings are unverified signals.', ''];
  for (const f of findings) {
    L.push(`## ${f.title}`, '', `- Status: **${f.status}** · Category: ${f.category} · Severity: ${f.severity} · Confidence: ${f.confidence}`, `- Endpoint: \`${f.method} ${f.endpoint}\``);
    if (f.sourceIdentity || f.targetIdentity) L.push(`- Identities: ${f.sourceIdentity ?? '—'} → ${f.targetIdentity ?? '—'}`);
    if (f.originalIdentifier != null) L.push(`- Identifier: \`${f.originalIdentifier}\` → \`${f.modifiedIdentifier}\``);
    if (f.redirect) L.push(`- Redirect: original ${f.redirect.originalStatus}, Location \`${f.redirect.location}\`, body ${f.redirect.inspectionStatus}`);
    if (f.requestRefs && Object.keys(f.requestRefs).length) L.push(`- Request/response references: ${Object.entries(f.requestRefs).map(([k, v]) => `${k}=${v}`).join(', ')}`);
    L.push('', `**Impact:** ${f.impact ?? ''}`, '');
    if (f.sensitiveSignals?.length) { L.push('**Sensitive signals (redacted):**'); f.sensitiveSignals.forEach((s) => L.push(`- ${s.category} @ ${s.field} (${s.where}): ${s.redacted}`)); L.push(''); }
    if (f.evidence) L.push('**Evidence:**', '```json', JSON.stringify(f.evidence, null, 2), '```', '');
    if (f.semanticDiff?.length) { L.push('**Semantic diff:**'); f.semanticDiff.slice(0, 15).forEach((c) => L.push(`- ${c.kind}${c.field ? ` \`${c.field}\`` : ''}${c.detail ? `: ${c.detail}` : ''} — ${c.matters}`)); L.push(''); }
    if (f.reproduction?.length) { L.push('**Reproduction:**'); f.reproduction.forEach((s, i) => L.push(`${i + 1}. ${s}`)); L.push(''); }
    if (f.remediation) L.push(`**Remediation:** ${f.remediation}`, '');
  }
  return L.join('\n');
}
