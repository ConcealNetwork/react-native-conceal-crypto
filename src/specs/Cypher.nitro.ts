import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Cypher module for IETF ChaCha stream ciphers
 *
 * IETF layout: 32-byte key, 12-byte nonce, 32-bit block counter starting at 0.
 * Same arguments and output as conceal-lib-js `cypher.chacha8/12/20(key, nonce, data)`.
 * Symmetric: XORs data with the keystream, so encrypt and decrypt are the same call.
 */
export interface Cypher extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * ChaCha8 (IETF) encrypt/decrypt
   *
   * @param key - 32-byte key
   * @param nonce - 12-byte nonce
   * @param data - plaintext or ciphertext
   * @returns data XORed with the ChaCha8 keystream (same length as data)
   * @throws Error (invalid argument) if key is not 32 bytes or nonce is not 12 bytes
   * @throws Error (range error) if data is longer than 2^32 × 64 bytes
   */
  chacha8(key: ArrayBuffer, nonce: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;

  /**
   * ChaCha12 (IETF) encrypt/decrypt
   *
   * @param key - 32-byte key
   * @param nonce - 12-byte nonce
   * @param data - plaintext or ciphertext
   * @returns data XORed with the ChaCha12 keystream (same length as data)
   * @throws Error (invalid argument) if key is not 32 bytes or nonce is not 12 bytes
   * @throws Error (range error) if data is longer than 2^32 × 64 bytes
   */
  chacha12(key: ArrayBuffer, nonce: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;

  /**
   * ChaCha20 (IETF) encrypt/decrypt
   *
   * @param key - 32-byte key
   * @param nonce - 12-byte nonce
   * @param data - plaintext or ciphertext
   * @returns data XORed with the ChaCha20 keystream (same length as data)
   * @throws Error (invalid argument) if key is not 32 bytes or nonce is not 12 bytes
   * @throws Error (range error) if data is longer than 2^32 × 64 bytes
   */
  chacha20(key: ArrayBuffer, nonce: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
}
