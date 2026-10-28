import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { mnemonic } from 'conceal-lib-js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildMnemonic, root, skipMnemonic } from './helpers/native';

type Case = { key: string; mnemonic: string };
type RejectEncode = { id: string; hex: string; note: string };
type RejectDecode = { id: string; phrase: string; note: string };
type Fixture = {
  oracle: string;
  cases: Case[];
  rejects: { encode: RejectEncode[]; decode: RejectDecode[] };
};

const fixture: Fixture = JSON.parse(
  readFileSync(join(root, 'test/fixtures/mnemonic.json'), 'utf8')
);

describe('conceal-lib-js mnemonic oracle', () => {
  it.each(fixture.cases.map((c) => [c.key.slice(0, 8), c]))('round-trips %s…', (_, c) => {
    expect(mnemonic.mn_encode(c.key)).toBe(c.mnemonic);
    expect(mnemonic.mn_decode(c.mnemonic)).toBe(c.key);
  });

  it('rejects bad encode hex (live oracle)', () => {
    expect(() => mnemonic.mn_encode('ab')).toThrow();
  });
});

describe('fixtures', () => {
  it.each(fixture.cases.map((c) => [c.key.slice(0, 8), c]))(
    'match live oracle encode/decode: %s…',
    (_, c) => {
      expect(mnemonic.mn_encode(c.key)).toBe(c.mnemonic);
      expect(mnemonic.mn_decode(c.mnemonic)).toBe(c.key);
    }
  );
});

describe.skipIf(skipMnemonic)('native mnemonics (C++ ↔ conceal-lib-js)', () => {
  let native: ReturnType<typeof buildMnemonic>;

  beforeAll(() => {
    native = buildMnemonic();
  });

  afterAll(() => native?.cleanup());

  it.each(fixture.cases.map((c) => [c.key.slice(0, 8), c]))('encode matches: %s…', (_, c) => {
    const res = native.exec('encode', c.key);
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.mnemonic);
  });

  it.each(fixture.cases.map((c) => [c.key.slice(0, 8), c]))('decode matches: %s…', (_, c) => {
    const res = native.exec('decode', ...c.mnemonic.split(' '));
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.key);
  });

  it.each(fixture.rejects.encode.map((r) => [r.id, r]))('encode rejects %s', (_, r) => {
    expect(native.exec('encode', r.hex).status).toBe(1);
  });

  it.each(fixture.rejects.decode.map((r) => [r.id, r]))('decode rejects %s', (_, r) => {
    const args = r.phrase.trim() === '' ? [''] : r.phrase.split(/\s+/);
    expect(native.exec('decode', ...args).status).toBe(1);
  });
});
