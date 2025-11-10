import type { HybridObject } from 'react-native-nitro-modules';
import type { Cryptonote } from './Cryptonote.nitro';
import type { Mnemonics } from './Mnemonics.nitro';

export interface ConcealCrypto extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  // Basic crypto functions
  hextobin(hex: string): ArrayBuffer;
  bintohex(buffer: ArrayBuffer): string;
  bin2base64(buffer: ArrayBuffer): string;
  base642bin(base64: string): ArrayBuffer;
  chacha8(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer;
  chacha12(input: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer;
  hmacSha1(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
  random(bits: number): string;
  randomBytes(bytes: number): ArrayBuffer;
  secretbox(message: ArrayBuffer, nonce: ArrayBuffer, key: ArrayBuffer): ArrayBuffer;
  secretboxOpen(ciphertext: ArrayBuffer, nonce: ArrayBuffer, key: ArrayBuffer): ArrayBuffer | null;

  // Cryptonote elliptic curve operations
  readonly cryptonote: Cryptonote;

  // Mnemonics encoding/decoding operations
  readonly mnemonics: Mnemonics;
}
