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

  // Cryptonote elliptic curve operations
  readonly cryptonote: Cryptonote;

  // Mnemonics encoding/decoding operations
  readonly mnemonics: Mnemonics;

  // IETF ChaCha stream ciphers (12-byte nonce)
  readonly cypher: Cypher;
}
