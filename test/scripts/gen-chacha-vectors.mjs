// Generates test/fixtures/chacha.json from conceal-lib-js (oracle, IETF 12-byte nonce).
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cypher } from 'conceal-lib-js';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'fixtures', 'chacha.json');
const require = createRequire(import.meta.url);
const libVersion = JSON.parse(
  readFileSync(require.resolve('conceal-lib-js/package.json'), 'utf8')
).version;

const hex = (u8) => Buffer.from(u8).toString('hex');

/** 8-byte big-endian index: Conceal-2fa-app native IV. */
const be8 = (index) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(index), false);
  return b;
};

/** 12-byte big-endian index: conceal-wallet-sdk / legacy Cn nonce. */
const be12 = (index) => {
  const b = new Uint8Array(12);
  b.set(be8(index), 4);
  return b;
};

/** 8-byte BE index left-aligned in 12 bytes: Conceal-2fa-app JS fallback buffer. */
const leftPad12 = (index) => {
  const b = new Uint8Array(12);
  b.set(be8(index), 0);
  return b;
};

const key = Uint8Array.from({ length: 32 }, (_, i) => i);
const plaintexts = {
  short: new TextEncoder().encode('{2FA,v,conceal.network}\0\0\0\0'),
  long: Uint8Array.from({ length: 200 }, (_, i) => (i * 7) & 0xff),
};

const ciphers = ['chacha8', 'chacha12', 'chacha20'];
const indexes = [
  { id: 'A0', index: '0' },
  { id: 'A1', index: '1' },
  { id: 'AN', index: '256' },
  { id: 'AN', index: '4294967296' },
];

const cases = [];
for (const cipher of ciphers) {
  for (const [ptName, pt] of Object.entries(plaintexts)) {
    for (const { id, index } of indexes) {
      const nonce = be12(index);
      cases.push({
        id,
        cipher,
        index,
        plaintext: ptName,
        nativeIv: hex(be8(index)),
        oracleNonce: hex(nonce),
        ciphertext: hex(cypher[cipher](key, nonce, pt)),
      });
    }
    const index = '1';
    const nonce = leftPad12(index);
    cases.push({
      id: 'C-pad',
      cipher,
      index,
      plaintext: ptName,
      nativeIv: hex(be8(index)),
      oracleNonce: hex(nonce),
      ciphertext: hex(cypher[cipher](key, nonce, pt)),
    });
  }
}

const fixture = {
  generator: 'test/scripts/gen-chacha-vectors.mjs',
  oracle: `conceal-lib-js@${libVersion} cypher.* (IETF: 12-byte nonce, 32-bit counter)`,
  key: hex(key),
  plaintexts: Object.fromEntries(Object.entries(plaintexts).map(([k, v]) => [k, hex(v)])),
  cases,
};

writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${cases.length} cases to ${out}`);

const ietfOut = join(here, '..', 'fixtures', 'chacha-ietf.json');
const ietfNonces = [
  { id: 'zero', nonce: new Uint8Array(12) },
  ...indexes.map(({ index }) => ({ id: `be-${index}`, nonce: be12(index) })),
  { id: 'random', nonce: Buffer.from('a1b2c3d4e5f60718293a4b5c', 'hex') },
];

const ietfCases = [];
for (const cipher of ciphers) {
  for (const { id, nonce } of ietfNonces) {
    for (const pt of Object.values(plaintexts)) {
      ietfCases.push({
        id,
        cipher,
        key: hex(key),
        nonce: hex(nonce),
        plaintext: hex(pt),
        ciphertext: hex(cypher[cipher](key, nonce, pt)),
      });
    }
  }
}

const ietfFixture = {
  generator: 'test/scripts/gen-chacha-vectors.mjs',
  oracle: `conceal-lib-js@${libVersion} cypher.* (IETF: 12-byte nonce, 32-bit counter)`,
  cases: ietfCases,
};

writeFileSync(ietfOut, `${JSON.stringify(ietfFixture, null, 2)}\n`);
console.log(`wrote ${ietfCases.length} cases to ${ietfOut}`);
