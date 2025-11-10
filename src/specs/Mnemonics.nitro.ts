import type { HybridObject } from 'react-native-nitro-modules';

/**
 * Mnemonics module for encoding/decoding private keys to/from mnemonic phrases
 *
 * Uses native C++ implementation for performance and security.
 * Only supports English language (25-word mnemonics with checksum).
 *
 * Note: The private key is expected as a hex string (64 characters = 32 bytes),
 * matching the format used in TypeScript where keys are stored as hex strings.
 * The C++ mnemonics library expects crypto::SecretKey, so we convert hex -> SecretKey internally.
 */
export interface Mnemonics extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  /**
   * Encode a private key (hex string) into a mnemonic phrase
   *
   * This matches the TypeScript API where wallet.keys.priv.spend is a hex string.
   * Internally converts hex string to crypto::SecretKey before calling the C++ implementation.
   *
   * @param privateKeyHex - 64-character hex string (32 bytes) representing the private key
   * @returns Space-separated mnemonic phrase (25 words, English only)
   * @throws Error if private key is invalid or wrong length
   */
  mn_encode(privateKeyHex: string): string;

  /**
   * Decode a mnemonic phrase into a private key (hex string)
   *
   * @param mnemonicPhrase - Space-separated mnemonic phrase (25 words, English only)
   * @returns 64-character hex string (32 bytes) representing the private key
   * @throws Error if mnemonic phrase is invalid, has wrong checksum, or contains invalid words
   */
  mn_decode(mnemonicPhrase: string): string;
}
