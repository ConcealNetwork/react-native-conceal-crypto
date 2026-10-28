import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildNative, root, skipNative } from './helpers/native';

type Case = {
  id: string;
  cipher: 'chacha8' | 'chacha12' | 'chacha20';
  key: string;
  nonce: string;
  plaintext: string;
  ciphertext: string;
};
type Fixture = { oracle: string; cases: Case[] };

const fixture: Fixture = JSON.parse(
  readFileSync(join(root, 'test/fixtures/chacha-ietf.json'), 'utf8')
);
const header = readFileSync(join(root, 'cpp/chacha.h'), 'utf8');
const define = (name: string) => {
  const m = header.match(new RegExp(`#define\\s+${name}\\s+\\(?(-?\\d+)\\)?`));
  return m ? Number(m[1]) : undefined;
};
const errCode = (name: string) => {
  const v = define(name);
  expect(v, `${name} defined in cpp/chacha.h`).toBeLessThan(0);
  return -(v as number);
};

const rounds = (c: Case['cipher']) => c.replace('chacha', '');
const label = (c: Case) => `${c.cipher} ${c.id} ${c.plaintext.length / 2}B`;
const key32 = fixture.cases[0].key;
const nonce12 = '00'.repeat(12);

describe.skipIf(skipNative)('native chacha_ietf_xor (12-byte nonce, 32-bit counter)', () => {
  let native: ReturnType<typeof buildNative>;
  const ietf = (r: string, key: string, nonce: string, data: string) =>
    native.exec('ietf', r, key, nonce, data);

  beforeAll(() => {
    native = buildNative();
  });

  afterAll(() => native?.cleanup());

  it.each(fixture.cases.map((c) => [label(c), c]))('matches oracle: %s', (_, c) => {
    const res = ietf(rounds(c.cipher), c.key, c.nonce, c.plaintext);
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.ciphertext);
  });

  it.each(fixture.cases.map((c) => [label(c), c]))('decrypt round trip: %s', (_, c) => {
    const res = ietf(rounds(c.cipher), c.key, c.nonce, c.ciphertext);
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.plaintext);
  });

  it.each(['8', '12', '20'])('empty data -> empty output (rounds %s)', (r) => {
    const res = ietf(r, key32, nonce12, '');
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe('');
  });

  it.each([31, 33])('rejects %i-byte key', (n) => {
    const res = ietf('20', '00'.repeat(n), nonce12, '00');
    expect(res.status).toBe(errCode('CHACHA_ERR_KEY'));
    expect(res.stdout).toBe('');
  });

  it.each([8, 11, 13])('rejects %i-byte nonce', (n) => {
    const res = ietf('20', key32, '00'.repeat(n), '00');
    expect(res.status).toBe(errCode('CHACHA_ERR_NONCE'));
    expect(res.stdout).toBe('');
  });

  it.each(['7', '24'])('rejects %s rounds', (r) => {
    const res = ietf(r, key32, nonce12, '00');
    expect(res.status).toBe(errCode('CHACHA_ERR_ROUNDS'));
    expect(res.stdout).toBe('');
  });

  const maxLength = 2n ** 32n * BigInt(define('CHACHA_BLOCK_SIZE') ?? Number.NaN);

  it('accepts length 2^32 blocks', () => {
    expect(native.exec('ietf-len', '20', String(maxLength)).status).toBe(0);
  });

  const be8 = (index: number) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(index));
    return b.toString('hex');
  };
  const legacyCases = [8, 12].flatMap((r) =>
    [0, 1].flatMap((index) =>
      [fixture.cases[0].plaintext, fixture.cases[1].plaintext].map(
        (data) => [`chacha${r} iv=BE64(${index}) ${data.length / 2}B`, r, be8(index), data] as const
      )
    )
  );

  it('legacy fixtures cover short and multi-block data', () => {
    const sizes = legacyCases.map(([, , , data]) => data.length / 2);
    expect(Math.min(...sizes)).toBeLessThan(Number(define('CHACHA_BLOCK_SIZE')));
    expect(Math.max(...sizes)).toBeGreaterThan(Number(define('CHACHA_BLOCK_SIZE')));
  });

  it.each(legacyCases)('legacy == ietf(00000000 ‖ iv): %s', (_, r, iv, data) => {
    const legacy = native.run(r as 8 | 12, key32, iv, data);
    const modern = ietf(String(r), key32, `00000000${iv}`, data);
    expect(legacy.status).toBe(0);
    expect(modern.status).toBe(0);
    expect(modern.stdout).toBe(legacy.stdout);
  });

  it('rejects length 2^32 blocks + 1 byte', () => {
    const res = native.exec('ietf-len', '20', String(maxLength + 1n));
    expect(res.status).toBe(errCode('CHACHA_ERR_LENGTH'));
  });
});
