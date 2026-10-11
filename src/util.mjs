// Small shared helpers: RFC 3339 times, strict base64, and path joins that
// print the way the Rust CLI prints them.

import path from 'node:path';

// Join like Rust's PathBuf::join: append a separator only when the base does
// not already end with one, and never normalize what the user passed. Paths
// built this way appear in messages, which must match the Rust CLI byte for
// byte (PROMPTSIGN_HOME=C:/x prints as C:/x\trust there, not C:\x\trust).
export function joinRaw(base, ...parts) {
  let out = base;
  for (const p of parts) {
    const last = out[out.length - 1];
    const hasSep = last === '/' || (path.sep === '\\' && last === '\\');
    out = out === '' || hasSep ? out + p : out + path.sep + p;
  }
  return out;
}

export function nowSecs() {
  return Math.floor(Date.now() / 1000);
}

// Strict standard base64 (padding required, no stray bits), as the Rust
// verifier decodes it. null when the input is not canonical base64.
export function b64decode(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    return null;
  }
  const buf = Buffer.from(s, 'base64');
  return buf.toString('base64') === s ? buf : null;
}

// Howard Hinnant's civil_from_days: days since 1970-01-01 to [y, m, d].
function civilFromDays(z) {
  z += 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365,
  );
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return [yoe + era * 400 + (m <= 2 ? 1 : 0), m, d];
}

function daysFromCivil(y, m, d) {
  y = m <= 2 ? y - 1 : y;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = m > 2 ? m - 3 : m + 9;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

const pad = (n, w = 2) => String(n).padStart(w, '0');

// Epoch seconds as RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ).
export function formatIso8601(secs) {
  const days = Math.floor(secs / 86400);
  const rem = secs - days * 86400;
  const [y, mo, d] = civilFromDays(days);
  const h = Math.floor(rem / 3600);
  const mi = Math.floor((rem % 3600) / 60);
  return `${pad(y, 4)}-${pad(mo)}-${pad(d)}T${pad(h)}:${pad(mi)}:${pad(rem % 60)}Z`;
}

const INT = /^[+-]?\d+$/;

// Parse YYYY-MM-DDTHH:MM:SS[.fff]Z to epoch seconds, or null. Lenient on the
// fraction and the trailing Z, strict on the layout (same rules as Rust).
export function parseIso8601(s) {
  if (typeof s !== 'string') return null;
  s = s.trim();
  const t = s.indexOf('T');
  if (t === -1) return null;
  const dp = s.slice(0, t).split('-');
  if (dp.length !== 3 || !dp.every((x) => INT.test(x))) return null;
  const [y, mo, d] = dp.map(Number);
  const time = s
    .slice(t + 1)
    .replace(/Z+$/, '')
    .split('.')[0];
  const tp = time.split(':');
  if (tp.length < 2) return null;
  const [h, mi, se = '0'] = tp;
  if (![h, mi, se].every((x) => INT.test(x))) return null;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return daysFromCivil(y, mo, d) * 86400 + Number(h) * 3600 + Number(mi) * 60 + Number(se);
}
