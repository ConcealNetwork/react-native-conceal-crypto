import type { HybridObject } from 'react-native-nitro-modules';
import type { Cryptonote } from './Cryptonote.nitro';
import type { Cypher } from './Cypher.nitro';
import type { Mnemonics } from './Mnemonics.nitro';

export interface ConcealCrypto extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // Basic crypto functions
  hextobin(hex: string): ArrayBuffer;
  bintohex(buffer: ArrayBuffer): string;
  bin2base64(buffer: ArrayBuffer): string;
  base642bin(base64: string): ArrayBuffer;
  /**
   * ChaCha8, legacy djb layout (8-byte IV, 64-bit counter), kept for existing data.
   * New code should use `cypher.chacha8` with a 12-byte nonce; for an 8-byte IV `iv`,
   * `cypher.chacha8(key, 00 00 00 00 ‖ iv, input)` gives identical output.
   */
  chacha8(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer;
  /**
   * ChaCha12, legacy djb layout (8-byte IV, 64-bit counter), kept for existing data.
   * New code should use `cypher.chacha12` with a 12-byte nonce; for an 8-byte IV `iv`,
   * `cypher.chacha12(key, 00 00 00 00 ‖ iv, input)` gives identical output.
   */
  chacha12(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer;
  hmacSha1(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
  hmacSha256(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
  hmacSha512(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
  random(bits: number): string;
  randomBytes(bytes: number): ArrayBuffer;
  secretbox(message: ArrayBuffer, nonce: ArrayBuffer, key: ArrayBuffer): ArrayBuffer;
  secretboxOpen(ciphertext: ArrayBuffer, nonce: ArrayBuffer, key: ArrayBuffer): ArrayBuffer | null;
  /**
   * Argon2id v1.3 (RFC 9106), byte-identical to conceal-lib-js `crypto.argon2id` for the same
   * bytes and costs; same argument order, but raw bytes instead of hex. Resolves to a 32-byte key.
   * Supported subset (every wallet Envelope 3 profile): salt exactly 16 bytes, `parallelism` 1,
   * password ≤ 1024 bytes, `memoryKiB` 8–65536, `iterations` 1–64; values are never clamped.
   * Runs on a background thread, one derivation at a time. Invalid values (buffer sizes,
   * out-of-range or non-integer costs) and derivation failures reject the promise; wrong-typed
   * arguments are type errors thrown synchronously by the binding layer.
   */
  argon2id(
    password: ArrayBuffer,
    salt: ArrayBuffer,
    memoryKiB: number,
    iterations: number,
    parallelism: number
  ): Promise<ArrayBuffer>;

  // Cryptonote elliptic curve operations
  readonly cryptonote: Cryptonote;

  // Mnemonics encoding/decoding operations
  readonly mnemonics: Mnemonics;

  // IETF ChaCha stream ciphers (12-byte nonce)
  readonly cypher: Cypher;
}
