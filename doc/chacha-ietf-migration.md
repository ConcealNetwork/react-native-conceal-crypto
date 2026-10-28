# Migrating Conceal-2fa-app to IETF `cypher.*` ChaCha

This guide moves the Conceal-2fa-app transaction-message encryption from the legacy
`concealCrypto.chacha8/chacha12(input, key, iv)` calls to the IETF
`concealCrypto.cypher.chacha8/chacha12(key, nonce, data)` calls, which use the same
layout and argument order as conceal-lib-js `cypher.*`.

## 1. Why, and what stays the same

- Users keep every 2FA code. With the nonce built as shown below, the ciphertext is
  byte-identical to what the legacy calls produce.
- Old and new app versions interoperate: messages sent by either can be read by the other.
- No data migration is needed.

| API                                                   | Key      | Nonce / IV                           | Argument order       |
| ----------------------------------------------------- | -------- | ------------------------------------ | -------------------- |
| Legacy `concealCrypto.chacha8/chacha12`               | 32 bytes | 8-byte IV (djb layout)               | `(input, key, iv)`   |
| IETF `concealCrypto.cypher.chacha8/chacha12/chacha20` | 32 bytes | 12-byte nonce, 32-bit counter from 0 | `(key, nonce, data)` |

`cypher.*` throws an invalid-argument error if the key is not 32 bytes or the nonce is
not 12 bytes, and a range error if data is longer than 2^32 × 64 bytes.

## 2. Nonce construction

The 12-byte nonce is **4 zero bytes followed by the 8-byte big-endian message index**
(`0^4 ‖ BE64(index)`):

```typescript
if (!Number.isSafeInteger(index) || index < 0)
  throw new RangeError(`invalid message index: ${index}`);
const nonceBuffer = new ArrayBuffer(12); // zero-filled
new DataView(nonceBuffer).setBigUint64(4, BigInt(index), false); // false = big-endian
```

The guard matters: `setBigUint64` silently wraps a negative index (`-1` becomes
`2^64 − 1`), which yields a valid nonce and wrong plaintext instead of an error. Native
`cypher.*` cannot catch this because it only sees the 12-byte nonce.

> **Do not** build it as `BE64(index) ‖ 0^4` (for example `new Uint8Array(12).set(iv8)`,
> or `setBigUint64(0, …)` on a 12-byte buffer). That layout matches the legacy output only
> for index 0, where all bytes are zero, and **silently produces wrong ciphertext for
> index ≥ 1** (the second message extra in a transaction).

## 3. Call changes

### Send — `model/Cn.ts`

Current code (8-byte nonce at `Cn.ts:3027–3031`, native calls at `Cn.ts:3053–3056`):

```typescript
const nonceBuffer = new ArrayBuffer(8);
const nonceView = new DataView(nonceBuffer);
const index: number = 0; // Because we only have one message
nonceView.setBigUint64(0, BigInt(index), false); // false = big-endian
// ...
if (cipher === 'chacha8') {
  nativeResult = concealCrypto.chacha8(inputBuffer, keyBuffer, nonceBuffer);
} else if (cipher === 'chacha12') {
  nativeResult = concealCrypto.chacha12(inputBuffer, keyBuffer, nonceBuffer);
}
```

After:

```typescript
const nonceBuffer = new ArrayBuffer(8); // keep: still used by the JS fallback
const nonceView = new DataView(nonceBuffer);
const index: number = 0; // Because we only have one message
nonceView.setBigUint64(0, BigInt(index), false); // false = big-endian

const ietfNonce = new ArrayBuffer(12);
new DataView(ietfNonce).setBigUint64(4, BigInt(index), false); // 0^4 ‖ BE64(index)
// ...
if (cipher === 'chacha8') {
  nativeResult = concealCrypto.cypher.chacha8(keyBuffer, ietfNonce, inputBuffer);
} else if (cipher === 'chacha12') {
  nativeResult = concealCrypto.cypher.chacha12(keyBuffer, ietfNonce, inputBuffer);
}
```

The cipher names `'chacha8'` / `'chacha12'` passed in from `model/Wallet.ts:1020` and
`services/WalletService.ts:1099`, `:1253`, `:1377` do not change.

### Receive — `model/TransactionsExplorer.ts` `decryptMessage`

`decryptMessage(index, …)` (`TransactionsExplorer.ts:324`) builds the 8-byte nonce at
`TransactionsExplorer.ts:365–368` and calls the native ciphers at `:387` (ChaCha12) and
`:399` (ChaCha8). `index` is the message-extra ordinal (`messageExtraIndex`,
`TransactionsExplorer.ts:481`/`:508`, passed at `:783`): 0 for the first message extra,
1 for a second.

Before:

```typescript
const nativeResult12 = concealCrypto.chacha12(inputBuffer, keyBuffer, nonceBuffer);
// ...
const nativeResult8 = concealCrypto.chacha8(inputBuffer, keyBuffer, nonceBuffer);
```

After (keep `nonceBuffer` for the JS fallback):

```typescript
if (!Number.isSafeInteger(index) || index < 0)
  throw new RangeError(`invalid message index: ${index}`);
const ietfNonce = new ArrayBuffer(12);
new DataView(ietfNonce).setBigUint64(4, BigInt(index), false); // 0^4 ‖ BE64(index)

const nativeResult12 = concealCrypto.cypher.chacha12(keyBuffer, ietfNonce, inputBuffer);
// ...
const nativeResult8 = concealCrypto.cypher.chacha8(keyBuffer, ietfNonce, inputBuffer);
```

## 4. JS fallback caveat

`JSChaCha8` (`model/ChaCha8.ts:19`) takes a 12-byte buffer but uses the **djb layout**
internally (bytes 0–7 are the IV, the counter is a separate word). It is equivalent to the
legacy native call with the buffer the app builds today (`Cn.ts:3067–3069`,
`TransactionsExplorer.ts:415–417`):

```typescript
const nonceBuf12 = new Uint8Array(12);
nonceBuf12.set(new Uint8Array(nonceBuffer)); // 8-byte IV, then 4 zero bytes
const cha = new JSChaCha8(hashBuf, nonceBuf12);
```

It is **not** an IETF implementation. Either keep feeding it this existing buffer derived
from the 8-byte IV, unchanged, or drop the fallback. **Never pass it the IETF nonce.**
ChaCha12 has no JS fallback today.

## 5. Rollout order

1. Upgrade `react-native-conceal-crypto` to the release that contains `cypher`. This alone
   changes no behavior.
2. Switch receive (`TransactionsExplorer.decryptMessage`), then send (`Cn.ts`), in one app
   release.
3. Verify (checklist below).
4. The legacy `concealCrypto.chacha8/chacha12` calls remain available for rollback.

## 6. Verification checklist

- [ ] After the upgrade, rescan the wallet and confirm existing on-chain 2FA messages still decrypt.
- [ ] Send create and delete smart messages, then read them back.
- [ ] Cross-check one message against conceal-lib-js / conceal-wallet-sdk (same key, nonce, and ciphertext).
- [ ] If available, decrypt a message with index 1 (a second message extra in one transaction).
- [ ] On device, confirm `cypher.chacha8` with an 8-byte nonce throws a JS `Error` ("chacha8: nonce must be 12 bytes") rather than crashing.
