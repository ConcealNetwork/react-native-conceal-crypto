// Generates test/fixtures/argon2id.json from conceal-lib-js (oracle: crypto.argon2id + secretbox).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crypto, secretbox } from 'conceal-lib-js';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'fixtures', 'argon2id.json');
const require = createRequire(import.meta.url);
const libVersion = JSON.parse(
  readFileSync(require.resolve('conceal-lib-js/package.json'), 'utf8')
).version;

const hex = (u8) => Buffer.from(u8).toString('hex');
const utf8 = (s) => new TextEncoder().encode(s);

const salts = [
  Uint8Array.from({ length: 16 }, (_, i) => i),
  Uint8Array.from({ length: 16 }, (_, i) => 0xff - i * 3),
];

const passwords = {
  empty: '',
  ascii: 'correct horse battery staple',
  utf8: 'пароль-кошелёк 🔐 Conceal',
  max: `${'a'.repeat(1022)}é`,
};
if (utf8(passwords.max).length !== 1024) throw new Error('max password must be 1024 bytes');

const smallCosts = [
  [8, 1, 1],
  [256, 2, 1],
  [4096, 3, 1],
];
const walletProfiles = [
  [19456, 2, 1],
  [32768, 3, 1],
  [65536, 3, 1],
];

const derive = (pw, salt, [m, t, p]) => ({
  password: hex(pw),
  salt: hex(salt),
  m,
  t,
  p,
  key: crypto.argon2id(hex(pw), hex(salt), m, t, p),
});

const cases = [];
for (const pw of Object.values(passwords)) {
  smallCosts.forEach((cost, i) => {
    cases.push(derive(utf8(pw), salts[i % salts.length], cost));
  });
}
walletProfiles.forEach((cost, i) => {
  cases.push(derive(utf8(passwords.ascii), salts[i % salts.length], cost));
});
cases.push(derive(utf8(passwords.utf8), salts[1], walletProfiles[1]));

const envPassword = 'wallet-pass-ключ-✓';
const kdf = {
  alg: 'argon2id',
  v: 19,
  m: 32768,
  t: 3,
  p: 1,
  salt: 'c0ffee00112233445566778899aabbcc',
};
const nonce = '0102030405060708090a0b0c0d0e0f101112131415161718';
const envKey = crypto.argon2id(hex(utf8(envPassword)), kdf.salt, kdf.m, kdf.t, kdf.p);
const inner = {
  envelope: 3,
  kdf,
  nonce,
  wallet: {
    deposits: [],
    withdrawals: [],
    transactions: [],
    lastHeight: 123456,
    nonce: '',
    creationHeight: 100000,
    coinAddressPrefix: 0x7ad4,
  },
};
const data = Array.from(
  secretbox(
    utf8(JSON.stringify(inner)),
    Uint8Array.from(Buffer.from(nonce, 'hex')),
    Uint8Array.from(Buffer.from(envKey, 'hex'))
  )
);

const fixture = {
  generator: 'test/scripts/gen-argon2id-vectors.mjs',
  oracle: `conceal-lib-js@${libVersion} crypto.argon2id (v0x13, 32-byte key) + secretbox`,
  cases,
  envelope3: {
    password: envPassword,
    wrongPassword: `${envPassword}!`,
    envelope: { envelope: 3, kdf, nonce, data },
  },
};

writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
// Biome reflows the envelope `data` byte array; keep the fixture `npm run check`-clean.
execFileSync(join(here, '..', '..', 'node_modules', '.bin', 'biome'), ['format', '--write', out]);
console.log(`wrote ${cases.length} cases + 1 envelope to ${out}`);
