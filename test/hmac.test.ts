/*
 * RFC conformance tests for the native HMAC implementation (cpp/Hmac.cpp).
 *
 * Vectors are taken verbatim from the official publications:
 * - RFC 2202, section 3: HMAC-SHA-1 test cases 1-7 (including the
 *   larger-than-block-size key cases; test case 5 is checked against the
 *   RFC's 96-bit truncation).
 * - RFC 4231, sections 4.2-4.8: HMAC-SHA-256 and HMAC-SHA-512 test cases
 *   1-7 (test case 5 is checked against the RFC's 128-bit truncation).
 *
 * The runner is a standalone C++ binary built from test/native/hmac_runner.cpp
 * and cpp/Hmac.cpp; it needs no Nitro runtime or RN host app.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildHmac, root, skipHmac } from './helpers/native';

type Case = {
  id: string;
  hash: 'sha1' | 'sha256' | 'sha512';
  key: string;
  data: string;
  hmac: string;
};
type Fixture = { oracle: string; cases: Case[] };

const fixture: Fixture = JSON.parse(readFileSync(join(root, 'test/fixtures/hmac.json'), 'utf8'));

const digestSizes: Record<Case['hash'], number> = { sha1: 40, sha256: 64, sha512: 128 };

describe.skipIf(skipHmac)('native HMAC (cpp/Hmac.cpp vs RFC vectors)', () => {
  let native: ReturnType<typeof buildHmac>;

  beforeAll(() => {
    native = buildHmac();
  }, 120_000);

  afterAll(() => native?.cleanup());

  it.each(fixture.cases.map((c) => [c.id, c]))('%s', (_, c) => {
    const res = native.exec(c.hash, c.key, c.data);
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe(c.hmac);
  });

  it.each(fixture.cases.map((c) => [c.id, c]))('%s digest length', (_, c) => {
    const res = native.exec(c.hash, c.key, c.data);
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toHaveLength(digestSizes[c.hash]);
  });

  it('RFC 2202 test case 5 honours the published 96-bit truncation', () => {
    const c = fixture.cases.find((x) => x.id === 'rfc2202-sha1-tc5');
    if (!c) throw new Error('missing fixture rfc2202-sha1-tc5');
    const res = native.exec(c.hash, c.key, c.data);
    expect(res.status).toBe(0);
    expect(res.stdout.trim().slice(0, 24)).toBe(c.hmac.slice(0, 24));
  });

  it('RFC 4231 test case 5 honours the published 128-bit truncation', () => {
    for (const id of ['rfc4231-tc5-sha256', 'rfc4231-tc5-sha512'] as const) {
      const c = fixture.cases.find((x) => x.id === id);
      if (!c) throw new Error(`missing fixture ${id}`);
      const res = native.exec(c.hash, c.key, c.data);
      expect(res.status).toBe(0);
      expect(res.stdout.trim().slice(0, 32)).toBe(c.hmac.slice(0, 32));
    }
  });
});
