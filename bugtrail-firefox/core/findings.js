// Turns observed comparisons into findings. Confidence, severity and impact are kept separate.
import { compare } from './diff.js';
import { detectSensitive, stripValues } from './sensitive.js';

const isRedirect = (s, redirectDetected) => Boolean(redirectDetected) || [301, 302, 303, 307, 308].includes(s);
const uid = () => (globalThis.crypto?.randomUUID?.() ?? `f-${Date.now()}-${Math.random().toString(16).slice(2)}`);

export const CATEGORIES = ['IDOR', 'BOLA', 'Horizontal Privilege Escalation', 'Vertical Privilege Escalation', 'Mass Assignment', 'Sensitive Data Exposure', 'Redirect Data Leakage', 'Authorization Inconsistency'];
export const STATUSES = ['Potential', 'Needs Verification', 'Verified', 'False Positive', 'Accepted Risk', 'Fixed'];

export function evaluateComparison(input) {
  const { baseline, modified, baseId, modId, endpoint, method = 'GET', sourceIdentity = null, targetIdentity = null, requestRefs = {}, modifiedIdObserved = true } = input;
  const diff = compare(baseline, modified, { modifiedId: modId });
  const redirect = isRedirect(modified.status, modified.redirectDetected);
  const statusKnown = modified.status != null;
  const redirectInfo = redirect ? { originalStatus: statusKnown ? modified.status : 'unknown (3xx — exact code unavailable; enable Enhanced redirect inspection in Settings for the real code)', location: modified.location ?? null, originalBodyAvailable: modified.bodyAvailable !== false && modified.body !== undefined, inspectionStatus: modified.bodyAvailable === false || modified.body === undefined ? (statusKnown ? 'not-inspected (Chrome/Firefox do not buffer the original redirect body — confirmed by testing)' : 'not-inspected (redirect was opaque to page scripts; status/Location/body all unavailable without Enhanced redirect inspection)') : 'inspected', followed: Boolean(modified.followed), finalDestination: modified.finalUrl ?? null } : null;
  const where = redirect ? 'redirect-original-body' : 'response-body';
  const baseSig = redirectInfo || modified.body === undefined ? detectSensitive(baseline.body, baseline.contentType, 'baseline') : detectSensitive(baseline.body, baseline.contentType, 'baseline');
  const modSig = modified.body === undefined ? [] : detectSensitive(modified.body, modified.contentType, where);
  const baseKeys = new Set(baseSig.map((s) => `${s.category}|${s._value}`));
  const fresh = modSig.filter((s) => !baseKeys.has(`${s.category}|${s._value}`));
  const sameIdentity = sourceIdentity && targetIdentity && sourceIdentity === targetIdentity;
  const crossAccount = baseId != null && modId != null && String(baseId) !== String(modId) && modifiedIdObserved && !sameIdentity;
  const findings = []; const notes = [];
  const base = { endpoint, method, sourceIdentity, targetIdentity, originalIdentifier: baseId, modifiedIdentifier: modId, requestRefs, semanticDiff: diff.changes, redirect: redirectInfo, createdAt: Date.now(), updatedAt: Date.now() };
  const mk = (o) => findings.push({ id: uid(), status: 'Potential', ...base, ...o, sensitiveSignals: stripValues(o.signals ?? fresh), signals: undefined });

  if (redirect && !redirectInfo.originalBodyAvailable) notes.push('Original redirect body was not exposed by the browser; not marked as inspected.');
  const pwd = fresh.filter((s) => s.category === 'password' && s.htmlInput);
  const secrets = fresh.filter((s) => ['api-key', 'token'].includes(s.category));
  const otherPwd = fresh.filter((s) => s.category === 'password' && !s.htmlInput);

  if (crossAccount && pwd.length) {
    mk({ title: 'Potential IDOR — Cross-Account Password Disclosure', category: 'IDOR', severity: /admin/i.test(`${modId} ${targetIdentity}`) ? 'critical' : 'high', confidence: 'medium', signals: pwd,
      impact: 'A password value is present in the server response for a different account, inside an input masked by the browser UI. It must not be used to log in.',
      reproduction: [`Capture baseline ${method} ${endpoint} with identifier "${baseId}".`, `Replace the identifier with the observed value "${modId}" (approved comparison).`, 'Inspect the response HTML for <input type="password"> with a non-placeholder value attribute (value redacted here).'],
      remediation: 'Enforce object-level authorization on the account endpoint and never render stored passwords into HTML.' });
  }
  if (crossAccount && secrets.length && redirect && redirectInfo.originalBodyAvailable) {
    mk({ title: 'Potential IDOR — Sensitive Data Exposed in Redirect Response', category: 'Redirect Data Leakage', severity: 'high', confidence: 'medium', signals: secrets,
      impact: `The original ${modified.status} response (Location: ${modified.location ?? 'n/a'}) carries a credential-like value that is not in the baseline. The browser follows the redirect and hides it.`,
      reproduction: [`Capture baseline ${method} ${endpoint} with "${baseId}".`, `Send the approved comparison with "${modId}" without following redirects.`, 'Inspect the original 3xx response body (redacted extract in evidence).'],
      remediation: 'Authorize the object before responding, and do not include data in redirect response bodies.' });
  } else if (crossAccount && secrets.length) {
    mk({ title: 'Potential IDOR — Cross-Account Sensitive Data Exposure', category: 'Sensitive Data Exposure', severity: 'high', confidence: 'medium', signals: secrets,
      impact: 'A credential-like value appears for a different identifier than the baseline.', reproduction: [`Compare ${method} ${endpoint} for "${baseId}" and "${modId}".`], remediation: 'Enforce object-level authorization and avoid returning secrets.' });
  }
  if (crossAccount && otherPwd.length && !pwd.length) {
    mk({ title: 'Potential IDOR — Password Field Returned for Another Identifier', category: 'Sensitive Data Exposure', severity: 'high', confidence: 'low', signals: otherPwd, impact: 'A password-named field with a non-placeholder value was returned.', reproduction: [`Compare ${method} ${endpoint} for "${baseId}" and "${modId}".`], remediation: 'Never return password values.' });
  }
  const sensitiveFound = pwd.length || secrets.length || otherPwd.length;
  const okBoth = baseline.status >= 200 && baseline.status < 300 && modified.status >= 200 && modified.status < 300;
  if (crossAccount && !sensitiveFound && okBoth && diff.changes.some((c) => /value-changed|field-added|html-structure/.test(c.kind))) {
    mk({ title: 'Potential Horizontal Privilege Escalation / IDOR', category: 'Horizontal Privilege Escalation', severity: 'medium', confidence: 'low', signals: [],
      impact: 'Replacing the identifier returned a different successful representation; authorization is not proven missing.', reproduction: [`Compare ${method} ${endpoint} for "${baseId}" and "${modId}".`, 'Confirm the second object belongs to another account.'], remediation: 'Verify the session owns the requested object server-side.' });
  }
  if (sameIdentity && fresh.length) notes.push('Sensitive value belongs to the same authorized identity: signal recorded, no cross-account classification.');
  if (redirect && !fresh.length && redirectInfo.originalBodyAvailable) notes.push('Redirect recorded; no sensitive data in original body.');
  return { diff, redirect: redirectInfo, signals: stripValues(modSig), newSignals: stripValues(fresh), findings, notes };
}

export function evaluateMassAssignment({ endpoint, method, identity, field, submittedValue, originalValue, responseValue, accepted, persisted }) {
  const verified = Boolean(accepted && persisted && String(responseValue) === String(submittedValue) && String(originalValue) !== String(submittedValue));
  return { id: uid(), title: verified ? 'Verified Mass Assignment / Privilege Escalation' : 'Potential Mass Assignment — User-Controlled Privilege Property', category: 'Mass Assignment', status: verified ? 'Verified' : 'Potential', endpoint, method, sourceIdentity: identity, severity: verified ? 'high' : 'medium', confidence: verified ? 'high' : (accepted ? 'medium' : 'low'), impact: 'A privilege-related property may be user-controllable.', evidence: { addedProperty: field, originalValue, submittedValue, responseValue, serverAccepted: accepted ?? null, persistenceVerified: Boolean(persisted) }, remediation: 'Use an allow-list of writable properties.', reproduction: [`Send approved ${method} ${endpoint} on a dedicated test account with additional property ${field}.`], createdAt: Date.now(), updatedAt: Date.now() };
}
export function evaluateVertical({ endpoint, method = 'GET', lowIdentity, highIdentity, lowResponse, highResponse }) {
  if (!(lowResponse.status >= 200 && lowResponse.status < 300 && highResponse.status >= 200 && highResponse.status < 300)) return null;
  const d = compare(highResponse, lowResponse);
  return { id: uid(), title: 'Potential Vertical Privilege Escalation', category: 'Vertical Privilege Escalation', status: 'Potential', endpoint, method, sourceIdentity: lowIdentity, targetIdentity: highIdentity, severity: 'medium', confidence: d.identical ? 'medium' : 'low', semanticDiff: d.changes, impact: 'A lower-privileged identity received a successful response from a function used by a higher-privileged identity.', remediation: 'Enforce role checks server-side.', reproduction: [`Request ${method} ${endpoint} as ${lowIdentity} and as ${highIdentity}; compare.`], createdAt: Date.now(), updatedAt: Date.now() };
}

// Privilege Escalation Review: same URL requested from two authenticated tabs (two identities).
// No identifier is substituted here — this compares access, not ownership of a specific object.
// "Verified" only when the lower-privileged side was clearly denied (401/403, or redirected to a
// login/denied page) AND the higher-privileged side succeeded AND the bodies are not just two
// copies of a generic error page. Everything else is "Potential" — a status-code difference alone
// never produces a verified finding.
const DENIAL_HINT = /login|sign[-_ ]?in|denied|forbidden|unauthoriz/i;
export function evaluatePrivilegeReview({ endpoint, method = 'GET', kind, lowIdentity, highIdentity, lowResponse, highResponse, requestRefs = {} }) {
  const d = compare(lowResponse, highResponse);
  const lowDenied = lowResponse.status === 401 || lowResponse.status === 403 || (isRedirect(lowResponse.status) && DENIAL_HINT.test(String(lowResponse.location ?? '')));
  const highOk = highResponse.status >= 200 && highResponse.status < 300 && (highResponse.body ?? '').length > 20;
  const lowOk = lowResponse.status >= 200 && lowResponse.status < 300;
  const bodiesDiffer = d.changes.some((c) => /value-changed|field-added|field-removed|html-structure/.test(c.kind));
  const title = kind === 'vertical' ? (lowDenied && highOk ? 'Potential Vertical Privilege Escalation — Needs Verification' : 'Potential Vertical Privilege Escalation') : (lowOk && highOk && bodiesDiffer ? 'Potential Horizontal Privilege Escalation / IDOR' : 'Potential Authorization Inconsistency');
  const status = lowDenied && highOk && kind === 'vertical' ? 'Needs Verification' : 'Potential';
  const confidence = lowDenied && highOk ? 'medium' : (lowOk && highOk ? 'low' : 'low');
  const sig = detectSensitive(highResponse.body, highResponse.contentType, 'privilege-review');
  return { id: uid(), title, category: kind === 'vertical' ? 'Vertical Privilege Escalation' : 'Horizontal Privilege Escalation', status, endpoint, method, sourceIdentity: lowIdentity, targetIdentity: highIdentity, severity: lowDenied && highOk ? 'high' : 'medium', confidence, semanticDiff: d.changes, requestRefs, sensitiveSignals: stripValues(sig), impact: lowDenied && highOk ? `"${lowIdentity}" was denied (${lowResponse.status}) while "${highIdentity}" succeeded on the same endpoint. Confirm manually that this is an authorization gap, not an expected role difference.` : `Both identities received a response; comparing for inconsistency. Status alone is not treated as proof.`, remediation: 'Enforce server-side role checks for this endpoint and verify they cannot be bypassed.', reproduction: [`Request ${method} ${endpoint} while authenticated as "${lowIdentity}".`, `Request ${method} ${endpoint} while authenticated as "${highIdentity}".`, 'Compare status, body and sensitive fields (see semantic diff).'], createdAt: Date.now(), updatedAt: Date.now() };
}
