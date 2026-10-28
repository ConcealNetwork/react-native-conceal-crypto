import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildArgon2id, root, skipArgon2id } from './helpers/native';

type Case = { password: string; salt: string; m: number; t: number; p: number; key: string };
type Kdf = { alg: string; v: number; m: number; t: number; p: number; salt: string };
type Envelope3 = { envelope: 3; kdf: Kdf; nonce: string; data: number[] };
type Fixture = {
  oracle: string;
  cases: Case[];
  envelope3: { password: string; wrongPassword: string; envelope: Envelope3 };
};

const fixture: Fixture = JSON.parse(
  readFileSync(join(root, 'test/fixtures/argon2id.json'), 'utf8')
);
const header = readFileSync(join(root, 'cpp/argon2id_kdf.h'), 'utf8');
const define = (name: string) => {
  const m = header.match(new RegExp(`#define\\s+${name}\\s+\\(?(-?\\d+)\\)?`));
  return m ? Number(m[1]) : undefined;
};
const errCode = (name: string) => {
  const v = define(name);
  expect(v, `${name} defined in cpp/argon2id_kdf.h`).toBeLessThan(0);
  return -(v as number);
};

const label = (c: Case) => `${c.password.length / 2}B pw, m=${c.m} t=${c.t} p=${c.p}`;
const valid = { pw: 16, salt: 16, m: 8, t: 1, p: 1 };
type Inputs = typeof valid;

describe.skipIf(skipArgon2id)('native argon2id_derive (libsodium Argon2id v0x13)', () => {
  let native: ReturnType<typeof buildArgon2id>;
  const check = (o: Partial<Inputs>) => {
    const v = { ...valid, ...o };
    return native.exec('check', ...[v.pw, v.salt, v.m, v.t, v.p].map(String));
  };

  beforeAll(() => {
    native = buildArgon2id();
  });

  afterAll(() => native?.cleanup());

  it.each(fixture.cases.map((c) => [label(c), c]))('matches oracle: %s', (_, c) => {
    const res = native.exec('derive', c.password, c.salt, String(c.m), String(c.t), String(c.p));
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.key);
  });

  const rejections: [string, Partial<Inputs>, string][] = [
    ['password 1025 bytes', { pw: 1025 }, 'ARGON2ID_ERR_PASSWORD'],
    ...[8, 15, 17, 64].map(
      (salt) =>
        [`salt ${salt} bytes`, { salt }, 'ARGON2ID_ERR_SALT'] as [string, Partial<Inputs>, string]
    ),
    ['p 2', { p: 2 }, 'ARGON2ID_ERR_PARALLELISM'],
    ['t 0', { t: 0 }, 'ARGON2ID_ERR_ITERATIONS'],
    ['t 65', { t: 65 }, 'ARGON2ID_ERR_ITERATIONS'],
    ['m 7', { m: 7 }, 'ARGON2ID_ERR_MEMORY'],
    ['m 65537', { m: 65537 }, 'ARGON2ID_ERR_MEMORY'],
  ];

  it.each(rejections)('check rejects %s', (_, o, code) => {
    expect(check(o).status).toBe(errCode(code));
  });

  it.each([
    ['m 8', { m: 8 }],
    ['m 65536', { m: 65536 }],
    ['t 1', { t: 1 }],
    ['t 64', { t: 64 }],
    ['password 1024 bytes', { pw: 1024 }],
  ] as [string, Partial<Inputs>][])('check accepts %s', (_, o) => {
    expect(check(o).status).toBe(0);
  });

  it('derive runs the check (salt 15 bytes)', () => {
    const c = fixture.cases[0];
    const res = native.exec('derive', c.password, c.salt.slice(2), String(c.m), String(c.t), '1');
    expect(res.status).toBe(errCode('ARGON2ID_ERR_SALT'));
    expect(res.stdout).toBe('');
  });

  const { envelope3 } = fixture;
  const hex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');
  const open = (password: string) => {
    const { kdf, nonce, data } = envelope3.envelope;
    return native.exec(
      'open',
      hex(new TextEncoder().encode(password)),
      kdf.salt,
      String(kdf.m),
      String(kdf.t),
      String(kdf.p),
      nonce,
      hex(Uint8Array.from(data))
    );
  };

  it('opens the SDK Envelope 3 with the correct password', () => {
    const res = open(envelope3.password);
    expect(res.status).toBe(0);
    const inner = JSON.parse(new TextDecoder().decode(Buffer.from(res.stdout.trim(), 'hex')));
    const outer = envelope3.envelope;
    expect(inner.envelope).toBe(3);
    expect(inner.kdf).toEqual(outer.kdf);
    expect(inner.nonce).toBe(outer.nonce);
    expect(typeof inner.wallet).toBe('object');
    expect(inner.wallet).not.toBeNull();
  });

  it('fails Envelope 3 authentication with the wrong password', () => {
    const res = open(envelope3.wrongPassword);
    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
  });
});
