import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { chacha20Poly1305Open } from '../src/chacha.js';
import { openSkln, parseSkln, unpackBundle, isSkln } from '../src/skln.js';
import { sealSkln } from './helpers.js';

const hex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const seal = (key, nonce, aad, plain) => {
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  return new Uint8Array(Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]));
};

test('ChaCha20-Poly1305 matches RFC 8439 section 2.8.2', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
  const nonce = hex('070000004041424344454647');
  const aad = hex('50515253c0c1c2c3c4c5c6c7');
  const plain = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const sealed = seal(key, nonce, aad, plain);
  assert.equal(Buffer.from(sealed.subarray(sealed.length - 16)).toString('hex'), '1ae10b594f09e26a7e902ecbd0600691');
  assert.deepEqual(chacha20Poly1305Open(key, nonce, aad, sealed), plain);
});

test('ChaCha20-Poly1305 agrees with node:crypto for every length around the block sizes', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  for (let n = 0; n <= 200; n++) {
    const plain = randomBytes(n);
    const aad = randomBytes(n % 37);
    const sealed = seal(key, nonce, aad, plain);
    assert.deepEqual(Buffer.from(chacha20Poly1305Open(key, nonce, aad, sealed)), plain, `length ${n}`);
  }
});

test('ChaCha20-Poly1305 refuses any changed byte, the aad, and short input', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const aad = new Uint8Array([1, 2, 3]);
  const sealed = seal(key, nonce, aad, randomBytes(70));
  for (let i = 0; i < sealed.length; i++) {
    const c = sealed.slice();
    c[i] ^= 0x80;
    assert.throws(() => chacha20Poly1305Open(key, nonce, aad, c), /tag mismatch/, `byte ${i}`);
  }
  assert.throws(() => chacha20Poly1305Open(key, nonce, new Uint8Array([1, 2, 4]), sealed), /tag mismatch/);
  assert.throws(() => chacha20Poly1305Open(key, nonce, aad, sealed.subarray(0, 15)), /bad ChaCha20-Poly1305 input/);
});

test('opens a .skln written with several record sizes, and reads its header without the key', async () => {
  const vek = randomBytes(32);
  for (const chunkLog2 of [12, 13, 20]) {
    const members = [['vault.json', randomBytes(10_000)], ['empty', new Uint8Array(0)], ['b', randomBytes(3)]];
    const file = sealSkln(vek, members, 77, chunkLog2);
    assert.ok(isSkln(file));
    const h = parseSkln(file);
    assert.equal(h.revision, 77n);
    assert.equal(h.kind, 1);
    assert.equal(h.chunkLog2, chunkLog2);
    const opened = await openSkln(vek, file);
    const back = unpackBundle(opened.plaintext);
    assert.deepEqual([...back.keys()], ['vault.json', 'empty', 'b']);
    assert.deepEqual(Buffer.from(back.get('vault.json')), Buffer.from(members[0][1]));
    assert.equal(back.get('empty').length, 0);
    await assert.rejects(openSkln(randomBytes(32), file), { code: 'corrupt' });
  }
});

test('a file that is not a .skln is refused', async () => {
  assert.equal(isSkln(new Uint8Array(3)), false);
  assert.throws(() => parseSkln(new TextEncoder().encode('SKIM and some more bytes, long enough for a header....')), { code: 'not-skln' });
  const file = sealSkln(randomBytes(32), [['a', new Uint8Array(1)]], 1, 12);
  const wrongVersion = file.slice();
  wrongVersion[8] = 2;
  assert.throws(() => parseSkln(wrongVersion), { code: 'not-skln' });
  const unknownFlag = file.slice();
  unknownFlag[9] = 2;
  assert.throws(() => parseSkln(unknownFlag), { code: 'corrupt' });
  for (const log2 of [11, 25]) {
    const bad = file.slice();
    bad[11] = log2;
    assert.throws(() => parseSkln(bad), { code: 'corrupt' });
  }
});

test('the bundle reader checks every length and every name', () => {
  const le = (n, size) => {
    const b = Buffer.alloc(size);
    if (size === 2) b.writeUInt16LE(n);
    else b.writeUInt32LE(n);
    return b;
  };
  const bundle = (...members) =>
    new Uint8Array(Buffer.concat([le(members.length, 4), ...members.flatMap(([n, d]) => [le(Buffer.byteLength(n), 2), Buffer.from(n), le(d.length, 4), Buffer.from(d)])]));
  assert.equal(unpackBundle(bundle(['a', [1, 2]], ['b', []])).get('a').length, 2);
  const corrupt = { code: 'corrupt' };
  for (const bad of ['', '.', '..', 'a/b', 'a\\b', 'nul\0', 'tab\t', 'x'.repeat(256)]) {
    assert.throws(() => unpackBundle(bundle([bad, [1]])), corrupt, JSON.stringify(bad));
  }
  assert.throws(() => unpackBundle(bundle(['a', [1]], ['a', [2]])), corrupt, 'duplicate name');
  const ok = bundle(['a', [1, 2, 3]]);
  for (let len = 0; len < ok.length; len++) assert.throws(() => unpackBundle(ok.slice(0, len)), corrupt, `cut ${len}`);
  assert.throws(() => unpackBundle(Uint8Array.from([...ok, 0])), corrupt, 'trailing byte');
  assert.throws(() => unpackBundle(new Uint8Array(Buffer.concat([le(1025, 4)]))), corrupt, 'too many members');
  const huge = Buffer.concat([le(1, 4), le(1, 2), Buffer.from('a'), le(0xffffffff, 4)]);
  assert.throws(() => unpackBundle(new Uint8Array(huge)), corrupt, 'a length past the end');
});
