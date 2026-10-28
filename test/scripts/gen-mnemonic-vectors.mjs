// Generates test/fixtures/mnemonic.json from conceal-lib-js (oracle: mnemonic.mn_encode/mn_decode).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mnemonic } from 'conceal-lib-js';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'fixtures', 'mnemonic.json');
const require = createRequire(import.meta.url);
const libVersion = JSON.parse(
  readFileSync(require.resolve('conceal-lib-js/package.json'), 'utf8')
).version;

const keys = [
  '0'.repeat(64),
  'a'.repeat(64),
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc',
  'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
];

const cases = keys.map((key) => {
  const phrase = mnemonic.mn_encode(key);
  const decoded = mnemonic.mn_decode(phrase);
  if (decoded !== key.toLowerCase()) {
    throw new Error(`oracle round-trip failed for ${key}: got ${decoded}`);
  }
  const words = phrase.split(' ');
  if (words.length !== 25) throw new Error(`expected 25 words, got ${words.length}`);
  return { key: key.toLowerCase(), mnemonic: phrase };
});

const good = cases.find((c) => c.key !== '0'.repeat(64));
if (!good) throw new Error('need a non-zero key for reject fixtures');
const goodWords = good.mnemonic.split(' ');
const badChecksum = [...goodWords];
badChecksum[24] = badChecksum[24] === 'abbey' ? 'able' : 'abbey';
const unknownWord = [...goodWords];
unknownWord[0] = 'notaword';

const fixture = {
  generator: 'test/scripts/gen-mnemonic-vectors.mjs',
  oracle: `conceal-lib-js@${libVersion} mnemonic.mn_encode/mn_decode (english)`,
  cases,
  rejects: {
    encode: [
      { id: 'short-hex', hex: 'ab', note: 'not 64 hex chars' },
      { id: 'odd-hex', hex: 'a'.repeat(63), note: 'odd length' },
      { id: 'non-hex', hex: `${'g'.repeat(64)}`, note: 'invalid hex digit' },
    ],
    decode: [
      { id: 'too-few', phrase: goodWords.slice(0, 24).join(' '), note: '24 words' },
      { id: 'too-many', phrase: `${good.mnemonic} abbey`, note: '26 words' },
      { id: 'unknown-word', phrase: unknownWord.join(' '), note: 'word not in English list' },
      { id: 'bad-checksum', phrase: badChecksum.join(' '), note: 'checksum word wrong' },
      { id: 'empty', phrase: '', note: 'empty phrase' },
    ],
  },
};

writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
execFileSync(join(here, '..', '..', 'node_modules', '.bin', 'biome'), ['format', '--write', out]);
console.log(`wrote ${cases.length} cases + rejects to ${out}`);
