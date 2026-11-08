// Credential Test Manager: import / validate / dedupe / mask only. Passwords are never stored or displayed.
export function parseCredentials(text, filename = '') {
  const lines = String(text ?? '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const csv = /\.csv$/i.test(filename) || lines[0]?.includes(',');
  const valid = [], invalid = [], duplicates = [], seen = new Set(); const preview = [];
  lines.slice(0, 500).forEach((line, i) => {
    if (i === 0 && /^(label|username|user|email)\b/i.test(line) && /,|:/.test(line)) return;
    const parts = csv ? line.split(',').map((x) => x.trim()) : line.split(/[:\t]/).map((x) => x.trim());
    let label, username, password;
    if (csv && parts.length >= 3) [label, username, password] = parts; else [username, password] = parts.length >= 2 ? [parts[0], parts[1]] : [parts[0], '']; 
    if (!username || /\s/.test(username) || username.length > 120) { invalid.push({ line: i + 1, reason: 'Invalid username' }); preview.push({ line: i + 1, label: label ?? '', username: username ?? '', password: '', state: 'invalid' }); return; }
    if (seen.has(username.toLowerCase())) { duplicates.push({ line: i + 1, username }); preview.push({ line: i + 1, label: label ?? '', username, password: '••••••••', state: 'duplicate' }); return; }
    seen.add(username.toLowerCase()); valid.push({ label: label || username, username, hasPassword: Boolean(password) });
    preview.push({ line: i + 1, label: label || username, username, password: password ? '••••••••' : '', state: 'valid' });
  });
  return { rows: lines.length, valid, invalid, duplicates, preview };
}
