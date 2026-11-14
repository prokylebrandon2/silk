// RFC 6238 one-time passwords: Base32 and otpauth:// parsing, HMAC-SHA1/256/512 through WebCrypto.
// Mirrors core/src/otp.rs so a code here equals the one in the Android app.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(s) {
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    if (ch === ' ' || ch === '-' || ch === '=') continue;
    const v = ALPHABET.indexOf(ch.toUpperCase());
    if (v < 0) return null;
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return out.length ? Uint8Array.from(out) : null;
}

/** The query of an otpauth:// link as a Map with lower-case keys, or null when it has none. */
function queryOf(s) {
  const qi = s.indexOf('?');
  if (qi < 0) return null;
  const q = new Map();
  for (const kv of s.slice(qi + 1).split('&')) {
    const eq = kv.indexOf('=');
    if (eq < 0) continue;
    let k = kv.slice(0, eq);
    let v = kv.slice(eq + 1);
    try {
      k = decodeURIComponent(k);
      v = decodeURIComponent(v);
    } catch {
      // keep the raw text
    }
    q.set(k.toLowerCase(), v);
  }
  return q;
}

/** A bare Base32 secret or an otpauth://totp link. Returns null when it can't be read. */
export function parseOtp(input) {
  const s = (input || '').trim();
  if (!s) return null;
  if (!s.toLowerCase().startsWith('otpauth://')) {
    const secret = base32Decode(s);
    return secret ? { secret, digits: 6, period: 30, algo: 'SHA-1' } : null;
  }
  const q = queryOf(s);
  if (!q) return null;
  if (!q.has('secret')) return null;
  const secret = base32Decode(q.get('secret'));
  if (!secret) return null;
  const a = (q.get('algorithm') || '').toUpperCase();
  const algo = a === 'SHA256' ? 'SHA-256' : a === 'SHA512' ? 'SHA-512' : 'SHA-1';
  const digits = Math.min(8, Math.max(6, parseInt(q.get('digits') || '6', 10) || 6));
  const period = Math.max(1, parseInt(q.get('period') || '30', 10) || 30);
  return { secret, digits, period, algo };
}

/** The name and account an otpauth:// link carries, for a new authenticator. A bare setup key has neither. */
export function otpLabel(input) {
  const s = (input || '').trim();
  if (!s.toLowerCase().startsWith('otpauth://')) return { title: '', username: '' };
  const slash = s.indexOf('/', 'otpauth://'.length);
  const path = slash < 0 ? '' : s.slice(slash + 1).split('?')[0];
  let label = path;
  try {
    label = decodeURIComponent(path);
  } catch {
    // keep the raw text
  }
  const colon = label.indexOf(':');
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  const issuer = ((queryOf(s) || new Map()).get('issuer') || (colon >= 0 ? label.slice(0, colon) : '')).trim();
  return { title: issuer || account, username: account };
}

export async function totpCode(p, unixSecs) {
  const counter = Math.floor(unixSecs / p.period);
  const msg = new Uint8Array(8);
  // 53 bits are plenty for a counter; split by hand because JS shifts are 32-bit.
  const hi = Math.floor(counter / 4294967296);
  const lo = counter >>> 0;
  new DataView(msg.buffer).setUint32(0, hi);
  new DataView(msg.buffer).setUint32(4, lo);
  const key = await crypto.subtle.importKey('raw', p.secret, { name: 'HMAC', hash: p.algo }, false, ['sign']);
  const tag = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = tag[tag.length - 1] & 0x0f;
  const bin = ((tag[o] & 0x7f) << 24) | (tag[o + 1] << 16) | (tag[o + 2] << 8) | tag[o + 3];
  return String(bin % 10 ** p.digits).padStart(p.digits, '0');
}

export const secondsLeft = (p, unixSecs) => p.period - (unixSecs % p.period);

/** "123456" -> "123 456", "12345678" -> "1234 5678". */
export const groupCode = (c) => (c.length === 8 ? `${c.slice(0, 4)} ${c.slice(4)}` : `${c.slice(0, 3)} ${c.slice(3)}`);

