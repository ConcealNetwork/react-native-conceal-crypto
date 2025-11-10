/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 * 
 * This file is part of react-native-conceal-crypto.
 * 
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include "HybridMnemonics.hpp"
#include "HybridCryptonote.hpp"
#include "Mnemonics/Mnemonics.h"
#include "Cryptonote/CryptoTypes.h"
#include <stdexcept>
#include <cstring>

using namespace margelo::nitro;
using namespace margelo::nitro::concealcrypto;

// TAG constant for HybridObject registration
constexpr auto TAG = "Mnemonics";

/**
 * Constructor — must call HybridObject(TAG) base constructor.
 */
HybridMnemonics::HybridMnemonics() : HybridObject(TAG) {
}

/**
 * Encode a private key (hex string) into a mnemonic phrase.
 * 
 * @param privateKeyHex - 64-character hex string (32 bytes)
 * @returns Space-separated mnemonic phrase (25 words)
 * @throws std::invalid_argument if hex string is invalid or wrong length
 */
std::string HybridMnemonics::mn_encode(const std::string& privateKeyHex) {
  // Validate hex string length (must be 64 chars = 32 bytes)
  if (privateKeyHex.length() != 64) {
    throw std::invalid_argument("Private key hex string must be exactly 64 characters (32 bytes)");
  }

  // Convert hex string to SecretKey using existing utility function
  crypto::SecretKey secretKey;
  
  if (!cryptonote_utils::hextobin(privateKeyHex, secretKey.data, 32)) {
    throw std::invalid_argument("Invalid hex string in private key");
  }

  // Convert SecretKey to mnemonic using native C++ implementation
  std::string mnemonic = mnemonics::privateKeyToMnemonic(secretKey);
  
  if (mnemonic.empty()) {
    throw std::runtime_error("Failed to encode private key to mnemonic");
  }

  return mnemonic;
}

/**
 * Decode a mnemonic phrase into a private key (hex string).
 * 
 * @param mnemonicPhrase - Space-separated mnemonic phrase (25 words)
 * @returns 64-character hex string (32 bytes)
 * @throws std::invalid_argument if mnemonic is invalid or has wrong checksum
 */
std::string HybridMnemonics::mn_decode(const std::string& mnemonicPhrase) {
  if (mnemonicPhrase.empty()) {
    throw std::invalid_argument("Mnemonic phrase cannot be empty");
  }

  // Convert mnemonic to SecretKey using native C++ implementation
  crypto::SecretKey secretKey = mnemonics::mnemonicToPrivateKey(mnemonicPhrase);
  
  // Check if conversion failed (returns default-constructed key with all zeros)
  // A valid secret key should never be all zeros
  bool isAllZero = true;
  for (size_t i = 0; i < 32; ++i) {
    if (secretKey.data[i] != 0) {
      isAllZero = false;
      break;
    }
  }
  
  if (isAllZero) {
    throw std::invalid_argument("Invalid mnemonic phrase: wrong checksum, invalid words, or incorrect length");
  }

  // Convert SecretKey to hex string using existing utility function
  return cryptonote_utils::bintohex(secretKey.data, 32);
}

