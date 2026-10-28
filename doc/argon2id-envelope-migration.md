# Migrating Conceal-2fa-app wallet files to Envelope 3 (Argon2id)

This guide moves Conceal-2fa-app **wallet file export/import** from Envelope 2 (legacy
pad/clamp KDF) to Envelope 3 (Argon2id), using this library's `concealCrypto.argon2id`.
The source of truth is conceal-wallet-sdk `src/envelope.ts` and `docs/wallet-envelope.md`.

## 1. Why, and what stays the same

- Envelope 3 is the write format of conceal-wallet-sdk and conceal-next-wallet. Envelopes 1
  and 2 stay readable forever, so existing backups keep importing.
- On-device storage (`model/WalletRepository.ts`) is unchanged. Only file export/import
  (`services/WalletEnvelopeCodec.ts`, `services/WalletFileService.ts`) moves.

## 2. Wire format

```json
{
  "envelope": 3,
  "kdf": { "alg": "argon2id", "v": 19, "m": 32768, "t": 3, "p": 1, "salt": "<32 hex>" },
  "nonce": "<48 hex>",
  "data": [12, 250, 7]
}
```

- `kdf` is **closed**: exactly `{ alg, v, m, t, p, salt }` (extra keys reject), with
  `alg: "argon2id"` and `v: 19`.
- Salt is 16 random bytes and the nonce 24 random bytes, both lowercase hex. The nonce is raw
  bytes, not the legacy base64 trick.
- Open checks structural bounds first, then allows only `(m,t,p)` ∈ `(19456,2,1)`,
  `(32768,3,1)`, `(65536,3,1)`. Writes use `(32768,3,1)`.
- The secretbox plaintext is `{ envelope: 3, kdf, nonce, wallet }`. Inner and outer `kdf` must
  match (numeric fields type-strict, salt compared as decoded bytes), and so must the nonce bytes.
- The password is raw UTF-8 (`TextEncoder`), no pad/clamp, at most 1024 bytes. Save throws
  `RangeError` over the limit; open returns `null`.
- Size limits (`wallet-envelope.md`): `MAX_ENVELOPE_TEXT_CHARS` 134_217_728 (raw text),
  `MAX_ENVELOPE_JSON_CHARS` 33_554_432 (non-whitespace chars), `MAX_ENVELOPE_CIPHERTEXT_BYTES`
  8_388_608 (`data.length`). `WalletFileService.parseEncryptedWalletFile` should gate the
  text like the SDK's `parseEncryptedWalletJson` (strip BOM, check both lengths) **before**
  `JSON.parse`.

## 3. Open dispatch (fail-closed)

1. If `envelope` is present, it must be the number `3`; otherwise `null`.
2. Else `data[]` means Envelope 2: keep the existing `decryptEnvelopeToRaw` path unchanged.
3. Else `encryptedKeys[]` means Envelope 1 (only if the app wants to support it).
4. Else `null`.

`WalletFileService.isEncryptedEnvelope` today accepts any `{ data: [], nonce: string }`. **An
Envelope 3 file matches too**, so without dispatching on `envelope` first it is fed to the
legacy decrypt and fails. Fix it:

```typescript
private static isEncryptedEnvelope(value: unknown): value is RawFullyEncryptedWallet | Envelope3 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  if ('envelope' in candidate) return candidate.envelope === 3;
  return Array.isArray(candidate.data) && typeof candidate.nonce === 'string';
}
```

## 4. Code for `services/WalletEnvelopeCodec.ts`

A recipe, **not tested in this repo**. Port these from `envelope.ts` unchanged (they only need
the hex helpers below, with `Hex` as `string`): the `Envelope3Kdf`, `Envelope3` and
`ParsedClosedArgon2idKdf` types, `parseClosedArgon2idKdf`,
`parseEnvelope3Nonce`, `bytesEqual`, `isCiphertextByteArray`, `acceptEnvelope3KdfParams` (with
`ENVELOPE3_ALLOWED_PROFILES`) and `kdfParamsEqual`. `config`, `RawWallet` and
`RawFullyEncryptedWallet` are the file's existing imports. Until rollout step 3 (section 8),
keep the existing Envelope 2 `saveEncryptedWallet` and add only the open path below.

```typescript
import concealCrypto from 'react-native-conceal-crypto';

const MAX_ENVELOPE3_PASSWORD_BYTES = 1024;

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexDecode(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex');
  return Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
}

const canonicalizeHex = (hex: string): string => hexEncode(hexDecode(hex));

/** UTF-8 bytes in an ArrayBuffer of exactly that length (Nitro reads the whole buffer). */
function utf8Buffer(text: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer as ArrayBuffer;
  }
  const copy = bytes.slice().buffer as ArrayBuffer;
  bytes.fill(0);
  return copy;
}

function wipe(buffer: ArrayBuffer | null): void {
  if (buffer) new Uint8Array(buffer).fill(0);
}

export class WalletEnvelopeCodec {
  static async saveEncryptedWallet(raw: RawWallet, password: string): Promise<Envelope3> {
    const passwordBuffer = utf8Buffer(password);
    let key: ArrayBuffer | null = null;
    try {
      if (passwordBuffer.byteLength > MAX_ENVELOPE3_PASSWORD_BYTES) {
        throw new RangeError(`password UTF-8 length exceeds ${MAX_ENVELOPE3_PASSWORD_BYTES} bytes`);
      }
      const salt = concealCrypto.randomBytes(16);
      const nonce = concealCrypto.randomBytes(24);
      const nonceHex = hexEncode(new Uint8Array(nonce));
      const saltHex = hexEncode(new Uint8Array(salt));
      const kdf: Envelope3Kdf = { alg: 'argon2id', v: 19, m: 32768, t: 3, p: 1, salt: saltHex };
      key = await concealCrypto.argon2id(passwordBuffer, salt, kdf.m, kdf.t, kdf.p);
      if (key.byteLength !== 32) throw new Error('argon2id returned unexpected key length');
      const inner = utf8Buffer(JSON.stringify({ envelope: 3, kdf, nonce: nonceHex, wallet: raw }));
      try {
        const cipher = concealCrypto.secretbox(inner, nonce, key);
        return { envelope: 3, kdf, nonce: nonceHex, data: Array.from(new Uint8Array(cipher)) };
      } finally {
        wipe(inner);
      }
    } finally {
      wipe(passwordBuffer);
      wipe(key);
    }
  }

  static async openEnvelope3(obj: Record<string, unknown>, password: string) {
    const kdf = parseClosedArgon2idKdf(obj.kdf);
    if (kdf === null || !acceptEnvelope3KdfParams(kdf)) return null;
    const nonce = parseEnvelope3Nonce(obj.nonce);
    if (nonce === null || !isCiphertextByteArray(obj.data)) return null;

    const passwordBuffer = utf8Buffer(password);
    let key: ArrayBuffer | null = null;
    try {
      if (passwordBuffer.byteLength > MAX_ENVELOPE3_PASSWORD_BYTES) return null;
      const salt = kdf.saltBytes.buffer as ArrayBuffer;
      key = await concealCrypto.argon2id(passwordBuffer, salt, kdf.m, kdf.t, kdf.p);
      if (key.byteLength !== 32) return null;
      const box = Uint8Array.from(obj.data).buffer;
      const plain = concealCrypto.secretboxOpen(box, nonce.buffer as ArrayBuffer, key);
      if (plain === null) return null;

      const inner = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown> | null;
      if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) return null;
      if (inner.envelope !== 3) return null;
      const innerKdf = parseClosedArgon2idKdf(inner.kdf);
      if (innerKdf === null || !kdfParamsEqual(kdf, innerKdf)) return null;
      const innerNonce = parseEnvelope3Nonce(inner.nonce);
      if (innerNonce === null || !bytesEqual(nonce, innerNonce)) return null;
      const wallet = inner.wallet;
      if (typeof wallet !== 'object' || wallet === null || Array.isArray(wallet)) return null;

      const raw = wallet as RawWallet;
      const prefix = raw.coinAddressPrefix;
      return prefix !== undefined && prefix !== config.addressPrefix ? null : raw;
    } catch {
      return null;
    } finally {
      wipe(passwordBuffer);
      wipe(key);
    }
  }

  static async openEnvelope(envelope: unknown, password: string): Promise<RawWallet | null> {
    if (!password || typeof envelope !== 'object' || envelope === null) return null;
    const obj = envelope as Record<string, unknown>;
    if ('envelope' in obj) {
      return obj.envelope === 3 ? WalletEnvelopeCodec.openEnvelope3(obj, password) : null;
    }
    if (!Array.isArray(obj.data)) return null;
    return WalletEnvelopeCodec.decryptEnvelopeToRaw(obj as RawFullyEncryptedWallet, password);
  }

  // decryptEnvelopeToRaw (Envelope 2) stays as it is today.
}
```

## 5. Async ripple

`WalletFileService.createEncryptedEnvelope`, `createExportFileContent`, `decryptWalletImport`
and `decryptWalletFromFile` become `async` and call `await WalletEnvelopeCodec.saveEncryptedWallet`
/ `openEnvelope`. Their envelope type becomes `RawFullyEncryptedWallet | Envelope3`.
`WalletEnvelopeCodec.openEncryptedWallet` becomes `async` too:
`const raw = await WalletEnvelopeCodec.openEnvelope(envelope, password)`, then
`Wallet.loadFromRaw(raw)` as today. Update:

- `screens/SettingsScreen.tsx` (around line 464): `await WalletFileService.createExportFileContent(wallet, exportPassword)`.
- `services/ImportService.ts` (around lines 239–244): `await WalletFileService.decryptWalletImport(envelope, filePassword)`;
  the `importResult` type becomes `Awaited<ReturnType<typeof WalletFileService.decryptWalletImport>>`.
- `tests/WalletEnvelopeCodec.unit.test.ts` and `tests/WalletFileService.unit.test.ts`: they call
  or mock the codec synchronously; switch to `await` / `mockResolvedValue`.

## 6. UX

Import already shows `'Decrypting backup…'` (`contexts/ImportProgressContext.tsx`). Wrap export
the same way, for example
`await getImportProgress().runWithImportProgress('Encrypting…', () => WalletFileService.createExportFileContent(wallet, exportPassword))`.
Expect roughly 32 MiB of memory and a noticeable delay. Derivation runs off the JS thread, so
the UI stays responsive.

## 7. Pitfalls

- Pass `u8.buffer` (an `ArrayBuffer`), never a typed array. In release builds Nitro does not
  type-check objects, so a `Uint8Array` is unsupported. If you slice, make sure the view covers
  the whole buffer.
- Wrong-typed arguments (`null`, `undefined`, a non-number, a wrong argument count) **throw
  synchronously** from the binding layer. Correctly typed but invalid values (a salt that isn't
  16 bytes, `p≠1`, out-of-range or non-integer costs) **reject the promise**. Wrap both in
  `try`/`await`.
- Envelope 3 open errors map to `null`, as `envelope.ts` does.
- The returned key `ArrayBuffer` is owned by JS and is **not zeroed** when garbage-collected.
  Overwrite it (`new Uint8Array(key).fill(0)`) after `secretbox`/`secretboxOpen`, and do the
  same for the password bytes buffer.
- Concurrent calls queue; they don't run in parallel.
- Profiles outside the native subset (`p>1`, other salt lengths) are not in the SDK allowlist anyway.

## 8. Rollout order

1. Upgrade `react-native-conceal-crypto` to the first release that contains `argon2id`.
2. Ship the Envelope 3 open path (sections 3–4), still writing Envelope 2.
3. Then switch writes to Envelope 3.

Older app builds can't import v3 files. Rollback is the previous app build; Envelope 2 files
stay readable.

## 9. Device checklist

- [ ] An export from the app opens in conceal-next-wallet, and an export from next-wallet opens in the app.
- [ ] An old Envelope 2 file still imports.
- [ ] A wrong password returns `null` ("Invalid password or corrupted wallet file").
- [ ] `argon2id` with an 8-byte salt rejects; with `null` it throws synchronously.
- [ ] Two concurrent exports both succeed (serialized).
- [ ] The UI stays responsive during derivation.
- [ ] A password over 1024 UTF-8 bytes is refused on export.

## 10. Future work

Moving on-device storage (`model/WalletRepository.ts`) to Argon2id is not part of this change.
