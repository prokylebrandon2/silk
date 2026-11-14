import test from 'node:test';
import assert from 'node:assert/strict';
import { openVault, unlockVault, sealVault, revisionOf, parseHeader, joinBackup } from '../src/vault.js';
import { generate, normalize, entropyBits, MIN_LEN, MAX_LEN } from '../src/generator.js';
import { blank, isLogin, subtitle, sameLogin } from '../src/entry.js';
import { importFile, exportCsv, exportJson } from '../src/transfer.js';
import { sealBundle } from './helpers.js';
import { parseOtp, totpCode, secondsLeft, groupCode } from '../src/totp.js';
import { urlMatches, hostOf } from '../src/match.js';

const entry = { id: 'a', title: 'GitHub', username: 'me', password: 'pw', url: 'https://github.com', otp: 'JBSWY3DPEHPK3PXP', notes: '' };

test('opens a Silk backup (key slot + vault file) with and without a key file', async () => {
  const kf = new Uint8Array(64).fill(7);
  const withKf = await sealBundle([entry], 'correct horse', kf);
  assert.equal(parseHeader(withKf).keyFile, true);
  const back = await openVault(withKf, 'correct horse', kf);
  assert.equal(back.length, 1);
  assert.equal(back[0].title, 'GitHub');
  assert.equal(back[0].otp, 'JBSWY3DPEHPK3PXP');
  await assert.rejects(openVault(withKf, 'wrong', kf), { code: 'wrong-credentials' });
  await assert.rejects(openVault(withKf, 'correct horse', new Uint8Array(64)), { code: 'wrong-credentials' });
  await assert.rejects(openVault(withKf, 'correct horse', null), { code: 'key-file-required' });

  const plain = await sealBundle([entry], 'password1', null);
  assert.equal(parseHeader(plain).keyFile, false);
  assert.equal((await openVault(plain, 'password1', null)).length, 1);
  await assert.rejects(openVault(plain, 'password1', kf), { code: 'key-file-not-used' });
});

test('rejects a tampered or truncated Silk backup', async () => {
  const b = await sealBundle([entry], 'password1', null);
  const SLOT_END = 5 + 91;
  const slot = b.slice();
  slot[5 + 20] ^= 1; // a salt byte: the key slot header is authenticated
  await assert.rejects(openVault(slot, 'password1', null), { code: 'wrong-credentials' });
  const wrapped = b.slice();
  wrapped[SLOT_END - 1] ^= 1; // the wrapped VEK
  await assert.rejects(openVault(wrapped, 'password1', null), { code: 'wrong-credentials' });
  const vault = b.slice();
  vault[vault.length - 1] ^= 1; // the vault file body: the password is right, the file was changed
  await assert.rejects(openVault(vault, 'password1', null), { code: 'corrupt' });
  const revision = b.slice();
  revision[SLOT_END + 13] ^= 1; // the revision is authenticated too
  await assert.rejects(openVault(revision, 'password1', null), { code: 'corrupt' });
  assert.throws(() => parseHeader(b.slice(0, 60)), { code: 'not-a-vault' });
  assert.throws(() => parseHeader(new TextEncoder().encode('not a vault file at all, no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no no')), { code: 'not-a-vault' });
  const wrongVersion = b.slice();
  wrongVersion[4] = 9;
  assert.throws(() => parseHeader(wrongVersion), { code: 'not-a-vault' });
  const absurd = b.slice();
  new DataView(absurd.buffer).setUint32(5 + 10, 0xffffffff);
  assert.throws(() => parseHeader(absurd), { code: 'corrupt' });
});

test('joins the two cloud files into the backup the app writes', async () => {
  const b = await sealBundle([entry], 'password1', null);
  const slot = b.slice(5, 5 + 91);
  const vault = b.slice(5 + 91);
  const joined = joinBackup(slot, vault);
  assert.deepEqual(Array.from(joined), Array.from(b));
  assert.equal((await openVault(joined, 'password1', null)).length, 1);
  assert.throws(() => joinBackup(slot.slice(0, 90), vault), { code: 'not-a-vault' });
  assert.throws(() => joinBackup(vault, slot), { code: 'not-a-vault' });
});

test('opens a .skln vault that spans many records', async () => {
  const many = Array.from({ length: 200 }, (_, i) => ({ ...entry, id: String(i), title: `Site ${i}`, notes: 'n'.repeat(150) }));
  const b = await sealBundle(many, 'password1', null, undefined, 9, 12);
  const vault = b.subarray(5 + 91);
  assert.ok(vault.length > 5 * 4096, 'more than a few 4 KiB records');
  const back = await openVault(b, 'password1', null);
  assert.equal(back.length, 200);
  assert.equal(back[199].title, 'Site 199');
  assert.equal(back[0].notes.length, 150);
});

test('rejects a damaged .skln vault file', async () => {
  const many = Array.from({ length: 100 }, (_, i) => ({ ...entry, id: String(i), notes: 'n'.repeat(150) }));
  const b = await sealBundle(many, 'password1', null, undefined, 3, 12);
  const at = 5 + 91; // where the .skln starts
  const record = 4 + 4096 + 16; // a full record with chunk_log2 = 12
  const flip = (offset) => {
    const c = b.slice();
    c[offset] ^= 1;
    return c;
  };
  const damaged = { code: 'corrupt' };
  await assert.rejects(openVault(flip(at + 9), 'password1', null), damaged); // flags
  await assert.rejects(openVault(flip(at + 11), 'password1', null), damaged); // chunk_log2
  await assert.rejects(openVault(flip(at + 13), 'password1', null), damaged); // revision
  await assert.rejects(openVault(flip(at + 20), 'password1', null), damaged); // salt
  await assert.rejects(openVault(flip(at + 36), 'password1', null), damaged); // a record length
  await assert.rejects(openVault(flip(at + 36 + 4 + 7), 'password1', null), damaged); // ciphertext
  await assert.rejects(openVault(flip(b.length - 1), 'password1', null), damaged); // last tag
  await assert.rejects(openVault(b.slice(0, b.length - 1), 'password1', null), damaged); // cut short
  await assert.rejects(openVault(b.slice(0, at + 36 + record), 'password1', null), damaged); // cut at a record boundary
  await assert.rejects(openVault(b.slice(0, at + 36 + 10), 'password1', null), damaged); // cut inside the first record
  await assert.rejects(openVault(Uint8Array.from([...b, 0]), 'password1', null), damaged); // appended byte
  const swapped = b.slice();
  swapped.set(b.subarray(at + 36, at + 36 + record), at + 36 + record);
  swapped.set(b.subarray(at + 36 + record, at + 36 + 2 * record), at + 36);
  await assert.rejects(openVault(swapped, 'password1', null), damaged); // two records swapped
  assert.equal((await openVault(b, 'password1', null)).length, 100); // the original is fine
});

// RFC 6238 appendix B vectors (8 digits). The seeds are the ASCII strings "1234567890" repeated to 20, 32 and 64 bytes.
const b32 = (str) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of Buffer.from(str)) bits += c.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
};
const seed = (n) => '1234567890'.repeat(7).slice(0, n);

test('TOTP matches the RFC 6238 vectors', async () => {
  const link = (n, algo) => `otpauth://totp/x?secret=${b32(seed(n))}&digits=8${algo ? `&algorithm=${algo}` : ''}`;
  const sha1 = parseOtp(link(20));
  const sha256 = parseOtp(link(32, 'SHA256'));
  const sha512 = parseOtp(link(64, 'SHA512'));
  assert.equal(await totpCode(sha1, 59), '94287082');
  assert.equal(await totpCode(sha1, 1111111109), '07081804');
  assert.equal(await totpCode(sha1, 20000000000), '65353130');
  assert.equal(await totpCode(sha256, 59), '46119246');
  assert.equal(await totpCode(sha512, 59), '90693936');
  assert.equal(secondsLeft(sha1, 59), 1);
  assert.equal(groupCode('123456'), '123 456');
  assert.equal(groupCode('12345678'), '1234 5678');
});

test('OTP input handling', () => {
  assert.equal(parseOtp(''), null);
  assert.equal(parseOtp('not base32 !!'), null);
  assert.deepEqual(parseOtp('jbsw y3dp-ehpk 3pxp').secret, parseOtp('JBSWY3DPEHPK3PXP').secret);
  assert.equal(parseOtp('otpauth://totp/Acme:me?issuer=Acme&secret=JBSWY3DPEHPK3PXP&period=60').period, 60);
  assert.equal(parseOtp('otpauth://totp/x'), null);
});

test('URL matching follows the app', () => {
  assert.ok(urlMatches('github.com', 'https://github.com/login'));
  assert.ok(urlMatches('https://www.github.com/a?b', 'https://gist.github.com/'));
  assert.ok(urlMatches('https://github.com:8443', 'https://www.github.com/'));
  assert.ok(!urlMatches('https://github.com', 'https://evilgithub.com/'));
  assert.ok(!urlMatches('https://github.com', 'https://github.com.evil.io/'));
  assert.ok(!urlMatches('', 'https://github.com'));
  assert.ok(!urlMatches('androidapp://com.example.app', 'https://example.com'));
  assert.ok(!urlMatches('https://github.com', 'chrome://settings'));
  assert.equal(hostOf('https://user@Example.com:81/x'), 'example.com');
});

test('saving writes the next revision under the same key slot, and the master password still opens it', async () => {
  const file = await sealBundle([entry], 'password1', null, undefined, 4);
  const { vek, revision, extras } = await unlockVault(file, 'password1', null);
  assert.equal(revision, 4n);
  const edited = [{ ...entry, title: 'GitHub (work)' }, { ...entry, id: 'b', title: 'Second' }];
  const sealed = await sealVault(file, vek, edited, extras, revision);
  assert.equal(sealed.revision, 5n);
  assert.equal(revisionOf(parseHeader(sealed.file)), 5n);
  assert.deepEqual(Array.from(parseHeader(sealed.file).slot), Array.from(parseHeader(file).slot));
  const back = await openVault(sealed.file, 'password1', null);
  assert.deepEqual(back.map((e) => e.title), ['GitHub (work)', 'Second']);
  await assert.rejects(openVault(sealed.file, 'wrong', null), { code: 'wrong-credentials' });
});

test('a vault saved twice keeps counting revisions and carries every field of an entry', async () => {
  const rich = { ...entry, kind: 'card', folder: 'f1', fields: [{ label: 'Card number', value: '4111', secret: true }] };
  const file = await sealBundle([rich], 'password1', null, undefined, 1);
  const first = await unlockVault(file, 'password1', null);
  const one = await sealVault(file, first.vek, first.entries, first.extras, first.revision);
  const second = await unlockVault(one.file, 'password1', null);
  const two = await sealVault(one.file, second.vek, second.entries, second.extras, second.revision);
  assert.equal(two.revision, 3n);
  const [back] = await openVault(two.file, 'password1', null);
  assert.equal(back.kind, 'card');
  assert.equal(back.folder, 'f1');
  assert.deepEqual(back.fields, [{ label: 'Card number', value: '4111', secret: true }]);
});

test('the generator honours length, character sets and look-alikes', () => {
  const all = { length: 30, lower: true, upper: true, digits: true, symbols: true, avoidLookalikes: true };
  for (let i = 0; i < 50; i++) {
    const p = generate(all);
    assert.equal(p.length, 30);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[0-9]/);
    assert.match(p, /[!@#$%^&*\-_=+?]/);
    assert.doesNotMatch(p, /[Il1O0o]/);
  }
  assert.match(generate({ ...all, lower: false, upper: false, symbols: false }), /^[0-9]+$/);
  assert.equal(normalize({ length: 3 }).length, MIN_LEN);
  assert.equal(normalize({ length: 500 }).length, MAX_LEN);
  assert.equal(normalize({ lower: false, upper: false, digits: false, symbols: false }).lower, true);
  assert.ok(entropyBits(all) > entropyBits({ ...all, length: 10 }));
});

test('items start as the app starts them, and logins are told apart like the app does', () => {
  assert.equal(blank('login').kind, '');
  assert.equal(isLogin(blank('login')), true);
  assert.equal(isLogin(blank('card')), false);
  assert.equal(blank('card').fields.length, 5);
  assert.equal(blank('identity').fields.length, 8);
  assert.equal(blank('note').fields.length, 0);
  const card = blank('card');
  card.fields[1].value = '4111 1111 1111 1234';
  assert.equal(subtitle(card), '•••• 1234');
  assert.equal(sameLogin({ title: 'A', username: 'U', url: 'x.com', password: 'p' }, { title: ' a ', username: 'u', url: 'X.com', password: 'p' }), true);
  assert.equal(sameLogin({ title: 'A', username: 'u', url: 'x.com', password: 'p' }, { title: 'A', username: 'u', url: 'x.com', password: 'P' }), false);
});

test('Proton Pass CSV and JSON exports can be read back', () => {
  const logins = [
    { ...blank('login'), title: 'GitHub', username: 'me@example.com', password: 'p,w"x', url: 'https://github.com', notes: 'two\nlines' },
    { ...blank('login'), title: 'Forum', username: 'me', password: 'secret', url: 'https://forum.example' },
  ];
  for (const text of [exportCsv(logins, 1700000000), exportJson(logins, 1700000000)]) {
    const { entries } = importFile(new TextEncoder().encode(text));
    assert.equal(entries.length, 2);
    assert.deepEqual(entries.map((e) => [e.title, e.username, e.password, e.url]), logins.map((e) => [e.title, e.username, e.password, e.url]));
    assert.equal(entries[0].notes, 'two\nlines');
  }
  assert.throws(() => importFile(new TextEncoder().encode('{"encrypted":true,"vaults":{}}')), { code: 'import' });
});
