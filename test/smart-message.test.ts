import { crypto as ccx, cypher } from 'conceal-lib-js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildNative, skipNative } from './helpers/native';

// Mirrors Conceal-2fa-app: Cn.ts (send) and TransactionsExplorer.decryptMessage (receive).
const CHECKSUM_SIZE = 4;
const MAX_CIPHERTEXT_BYTES = 255; // tx_extra message length is a single byte
const MAX_BODY_BYTES = MAX_CIPHERTEXT_BYTES - CHECKSUM_SIZE;

type Rounds = 8 | 12;
type Encrypt = (rounds: Rounds, keyHex: string, data: Uint8Array) => Uint8Array;

const hex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');
const utf8 = new TextEncoder();

/** Message index 0 (one message per tx): 8-byte BE for RN, 12-byte BE for lib-js / SDK. */
const RN_NONCE = '00'.repeat(8);
const LIB_NONCE = new Uint8Array(12);

function frame(body: string): Uint8Array {
  const raw = utf8.encode(body);
  const out = new Uint8Array(raw.length + CHECKSUM_SIZE);
  out.set(raw);
  return out;
}

function isSmartMessage(message: string): boolean {
  const t = message.trim();
  return t.startsWith('{') && t.endsWith('}');
}

function is2FASmartMessage(message: string): boolean {
  if (!isSmartMessage(message)) return false;
  const parts = message.trim().slice(1, -1).split(',');
  if (parts.length < 2) return false;
  return (
    parts[0].trim().toLowerCase() === '2fa' &&
    ['c', 'd', 'u'].includes(parts[1].trim().toLowerCase())
  );
}

/** Receiver logic: ChaCha12 if it yields a smart message, else ChaCha8; then checksum. */
function appDecrypt(decrypt: Encrypt, keyHex: string, cipher: Uint8Array): string | null {
  const strip = (buf: Uint8Array) => new TextDecoder().decode(buf).slice(0, -CHECKSUM_SIZE);
  const buf12 = decrypt(12, keyHex, cipher);
  const m12 = strip(buf12);
  const buf = is2FASmartMessage(m12) || isSmartMessage(m12) ? buf12 : decrypt(8, keyHex, cipher);
  if (!buf.slice(-CHECKSUM_SIZE).every((b) => b === 0)) return null;
  return new TextDecoder().decode(buf).slice(0, -CHECKSUM_SIZE);
}

const lib: Encrypt = (rounds, keyHex, data) =>
  cypher[rounds === 8 ? 'chacha8' : 'chacha12'](Buffer.from(keyHex, 'hex'), LIB_NONCE, data);

// Self-send, as WalletService does for 2FA sync: destination = own address.
const wallet = ccx.generate_keys('a1'.repeat(32));
const txKey = ccx.generate_keys('b2'.repeat(32));
const senderDerivation = ccx.generate_key_derivation(wallet.pub, txKey.sec);
const receiverDerivation = ccx.generate_key_derivation(txKey.pub, wallet.sec);
const messageKey = ccx.cn_fast_hash(`${senderDerivation}8000`);

const maxBody = (() => {
  const head = '{2FA,c,Conceal Network,';
  const tail = ',JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP,SHA512,8,60}';
  return `${head}${'x'.repeat(MAX_BODY_BYTES - head.length - tail.length)}${tail}`;
})();

const messages: { name: string; body: string; rounds: Rounds }[] = [
  {
    name: '2FA create (defaults)',
    body: '{2FA,c,GitHub,alice@example.com,JBSWY3DPEHPK3PXP}',
    rounds: 12,
  },
  {
    name: '2FA create (SHA256, 8 digits, 60s)',
    body: '{2FA,c,Google,bob.smith@gmail.com,HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ,SHA256,8,60}',
    rounds: 12,
  },
  {
    name: '2FA delete (tx hash)',
    body: '{2FA,d,3b2a5f0e9c8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b}',
    rounds: 12,
  },
  {
    name: '2FA create (UTF-8 issuer)',
    body: '{2FA,c,Société Générale,josé.müller@exemple.fr,KRSXG5CTMVRXEZLUKN2XAZLSNBXXI3TJ}',
    rounds: 12,
  },
  { name: '2FA create (max 251-byte body)', body: maxBody, rounds: 12 },
  { name: 'non-2FA smart message (ChaCha12)', body: '{vault,c,notes,encrypted-blob}', rounds: 12 },
  { name: 'plain chat message (ChaCha8)', body: 'Hello from Conceal 2FA!', rounds: 8 },
];

describe('smart message setup (realistic Conceal tx message)', () => {
  it('sender and receiver derive the same message key', () => {
    expect(receiverDerivation).toBe(senderDerivation);
    expect(messageKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it.each(messages.map((m) => [m.name, m]))('%s fits the on-chain size limit', (_, m) => {
    expect(frame(m.body).length).toBeLessThanOrEqual(MAX_CIPHERTEXT_BYTES);
  });

  it('max-size case is exactly at the limit', () => {
    expect(utf8.encode(maxBody).length).toBe(MAX_BODY_BYTES);
    expect(frame(maxBody).length).toBe(MAX_CIPHERTEXT_BYTES);
  });
});

describe.skipIf(skipNative)('smart message RN (native) <-> conceal-lib-js', () => {
  let native: ReturnType<typeof buildNative>;
  const rn: Encrypt = (rounds, keyHex, data) => {
    const res = native.run(rounds, keyHex, RN_NONCE, hex(data));
    if (res.status !== 0) throw new Error(res.stderr);
    return Buffer.from(res.stdout.trim(), 'hex');
  };

  beforeAll(() => {
    native = buildNative();
  });

  afterAll(() => {
    native?.cleanup();
  });

  describe.each(messages.map((m) => [m.name, m] as const))('%s', (_, m) => {
    const framed = frame(m.body);

    it('RN encrypt -> RN decrypt', () => {
      const ct = rn(m.rounds, messageKey, framed);
      expect(ct.length).toBe(framed.length);
      expect(appDecrypt(rn, messageKey, ct)).toBe(m.body);
    });

    it('RN encrypt -> lib decrypt', () => {
      const ct = rn(m.rounds, messageKey, framed);
      expect(appDecrypt(lib, messageKey, ct)).toBe(m.body);
    });

    it('lib encrypt -> RN decrypt', () => {
      const ct = lib(m.rounds, messageKey, framed);
      expect(appDecrypt(rn, messageKey, ct)).toBe(m.body);
    });

    it('RN and lib ciphertexts are identical', () => {
      expect(hex(rn(m.rounds, messageKey, framed))).toBe(hex(lib(m.rounds, messageKey, framed)));
    });

    it('wrong key does not decrypt', () => {
      const ct = lib(m.rounds, messageKey, framed);
      expect(appDecrypt(rn, 'ff'.repeat(32), ct)).toBeNull();
    });
  });
});

describe.skipIf(skipNative)('smart message IETF (native) <-> conceal-lib-js', () => {
  let native: ReturnType<typeof buildNative>;
  /** 12-byte IETF nonce for a legacy 8-byte IV: 0^4 ‖ iv. */
  const ietfNonce = (ivHex: string) => `${'00'.repeat(4)}${ivHex}`;
  const unwrap = (res: { status: number | null; stdout: string; stderr: string }) => {
    if (res.status !== 0) throw new Error(res.stderr);
    return Buffer.from(res.stdout.trim(), 'hex');
  };
  const legacyAt =
    (ivHex: string): Encrypt =>
    (rounds, keyHex, data) =>
      unwrap(native.run(rounds, keyHex, ivHex, hex(data)));
  const ietfAt =
    (nonceHex: string): Encrypt =>
    (rounds, keyHex, data) =>
      unwrap(native.exec('ietf', String(rounds), keyHex, nonceHex, hex(data)));
  const ietf = ietfAt(ietfNonce(RN_NONCE));
  const legacy = legacyAt(RN_NONCE);

  beforeAll(() => {
    native = buildNative();
  });

  afterAll(() => {
    native?.cleanup();
  });

  describe.each(messages.map((m) => [m.name, m] as const))('%s', (_, m) => {
    const framed = frame(m.body);

    it('IETF encrypt -> lib decrypt', () => {
      const ct = ietf(m.rounds, messageKey, framed);
      expect(hex(lib(m.rounds, messageKey, ct))).toBe(hex(framed));
      expect(appDecrypt(lib, messageKey, ct)).toBe(m.body);
    });

    it('lib encrypt -> IETF decrypt', () => {
      const ct = lib(m.rounds, messageKey, framed);
      expect(hex(ietf(m.rounds, messageKey, ct))).toBe(hex(framed));
      expect(appDecrypt(ietf, messageKey, ct)).toBe(m.body);
    });

    it('IETF, legacy and lib ciphertexts are identical', () => {
      const ct = hex(ietf(m.rounds, messageKey, framed));
      expect(ct).toBe(hex(legacy(m.rounds, messageKey, framed)));
      expect(ct).toBe(hex(lib(m.rounds, messageKey, framed)));
    });

    it('IETF encrypt -> IETF decrypt', () => {
      const ct = ietf(m.rounds, messageKey, framed);
      expect(ct.length).toBe(framed.length);
      expect(appDecrypt(ietf, messageKey, ct)).toBe(m.body);
    });
  });

  it('message index 1: IETF, legacy and lib ciphertexts are identical', () => {
    const m = messages[0];
    const framed = frame(m.body);
    const iv = Buffer.alloc(8);
    iv.writeBigUInt64BE(1n);
    const libNonce = new Uint8Array(12);
    libNonce[11] = 1;
    const libCt = cypher[m.rounds === 8 ? 'chacha8' : 'chacha12'](
      Buffer.from(messageKey, 'hex'),
      libNonce,
      framed
    );
    const ct = hex(ietfAt(ietfNonce(hex(iv)))(m.rounds, messageKey, framed));
    expect(ct).toBe(hex(legacyAt(hex(iv))(m.rounds, messageKey, framed)));
    expect(ct).toBe(hex(libCt));
    expect(ct).not.toBe(hex(ietf(m.rounds, messageKey, framed)));
  });
});
