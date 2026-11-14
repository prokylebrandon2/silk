// The password generator of the app's Generator tab (core/src/generator.rs): length, character sets
// and look-alike removal. Every selected set appears at least once; the rest is uniform over the pool.

export const MIN_LEN = 8;
export const MAX_LEN = 64;

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*-_=+?';
/** Characters that are easy to misread: l I 1 and O 0 o. */
const LOOKALIKES = 'Il1O0o';

export const DEFAULTS = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidLookalikes: true };

/** Length forced into range and at least one character set switched on. Unknown or missing values become the defaults. */
export function normalize(options) {
  const o = { ...DEFAULTS, ...options };
  o.length = Math.min(MAX_LEN, Math.max(MIN_LEN, Math.trunc(Number(o.length)) || DEFAULTS.length));
  for (const k of ['lower', 'upper', 'digits', 'symbols', 'avoidLookalikes']) o[k] = o[k] !== false;
  if (!(o.lower || o.upper || o.digits || o.symbols)) o.lower = true;
  return o;
}

/** The character sets that are switched on, each as a list of characters. */
function classes(o) {
  const sets = [];
  if (o.lower) sets.push(LOWER);
  if (o.upper) sets.push(UPPER);
  if (o.digits) sets.push(DIGITS);
  if (o.symbols) sets.push(SYMBOLS);
  return sets.map((s) => Array.from(s).filter((c) => !(o.avoidLookalikes && LOOKALIKES.includes(c)))).filter((s) => s.length > 0);
}

/** A rough strength figure: length x log2(pool size). */
export function entropyBits(options) {
  const o = normalize(options);
  const pool = classes(o).reduce((n, c) => n + c.length, 0);
  return o.length * Math.log2(pool);
}

/** Uniform random number below `n` (n > 0), without modulo bias. */
function below(n) {
  const limit = 2 ** 32 - (2 ** 32 % n);
  const r = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(r);
    if (r[0] < limit) return r[0] % n;
  }
}

export function generate(options) {
  const o = normalize(options);
  const sets = classes(o);
  const pool = sets.flat();
  const out = sets.map((set) => set[below(set.length)]);
  while (out.length < o.length) out.push(pool[below(pool.length)]);
  // Fisher-Yates, so the guaranteed characters don't sit at the front.
  for (let i = out.length - 1; i > 0; i--) {
    const j = below(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}
