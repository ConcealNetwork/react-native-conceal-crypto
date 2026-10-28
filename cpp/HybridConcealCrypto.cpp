/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include "HybridConcealCrypto.hpp"

#include <sodium.h>

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>

#include "HybridCryptonote.hpp"
#include "HybridMnemonics.hpp"
#include "argon2id_kdf.h"
#include "chacha.h"
#include "mn_random.h"

using namespace margelo::nitro;
using namespace margelo::nitro::concealcrypto;

// TAG constant for HybridObject registration
constexpr auto TAG = "ConcealCrypto";

/**
 * Constructor — must call HybridObject(TAG) base constructor.
 * Initialize the cryptonote, mnemonics and cypher sub-objects.
 */
HybridConcealCrypto::HybridConcealCrypto() : HybridObject(TAG) {
  // Initialize cryptonote sub-object
  _cryptonote = std::make_shared<HybridCryptonote>();
  // Initialize mnemonics sub-object
  _mnemonics = std::make_shared<HybridMnemonics>();
  // Initialize cypher sub-object
  _cypher = std::make_shared<HybridCypher>();
}

/**
 * Converts a hex string (e.g. "deadbeef") into binary bytes.
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::hextobin(const std::string& hex) {
  if (hex.size() % 2 != 0) throw std::invalid_argument("Hex string must have even length");

  std::vector<uint8_t> binary;
  binary.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
    binary.push_back(static_cast<uint8_t>(byte));
  }

  return ArrayBuffer::copy(binary);
}

/**
 * Converts binary bytes into a hex string.
 */
std::string HybridConcealCrypto::bintohex(const std::shared_ptr<ArrayBuffer>& buffer) {
  if (!buffer) throw std::invalid_argument("Buffer must not be null");

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  const uint8_t* data = static_cast<const uint8_t*>(buffer->data());
  for (size_t i = 0; i < buffer->size(); ++i) {
    oss << std::setw(2) << static_cast<int>(data[i]);
  }

  return oss.str();
}

/**
 * Converts binary bytes into a base64 string using libsodium.
 * Uses standard base64 with padding to match nacl.util.encodeBase64().
 */
std::string HybridConcealCrypto::bin2base64(const std::shared_ptr<ArrayBuffer>& buffer) {
  if (!buffer) throw std::invalid_argument("Buffer must not be null");

  const uint8_t* bin = static_cast<const uint8_t*>(buffer->data());
  size_t bin_len = buffer->size();

  // Calculate required base64 output size (standard variant with padding)
  size_t base64_len = sodium_base64_ENCODED_LEN(bin_len, sodium_base64_VARIANT_ORIGINAL);
  std::vector<char> base64(base64_len);

  // Convert to base64 using libsodium (standard variant)
  char* result =
      sodium_bin2base64(base64.data(), base64_len, bin, bin_len, sodium_base64_VARIANT_ORIGINAL);

  if (!result) throw std::runtime_error("Base64 encoding failed");

  return std::string(base64.data());
}

/**
 * Converts a base64 string into binary bytes using libsodium.
 * Uses standard base64 to match nacl.util.decodeBase64().
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::base642bin(const std::string& base64) {
  if (base64.empty()) throw std::invalid_argument("Base64 string must not be empty");

  // Allocate buffer for binary output (max size)
  std::vector<uint8_t> bin(base64.size());  // Max possible size
  size_t bin_len;

  // Convert from base64 using libsodium (standard variant)
  int result = sodium_base642bin(bin.data(), bin.size(), base64.c_str(), base64.size(),
                                 nullptr,   // ignore characters
                                 &bin_len,  // actual output length
                                 nullptr,   // base64_end (not needed)
                                 sodium_base64_VARIANT_ORIGINAL);

  if (result != 0) throw std::runtime_error("Base64 decoding failed");

  // Resize to actual length
  bin.resize(bin_len);

  return ArrayBuffer::copy(bin);
}

/**
 * ChaCha8 encryption.
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::chacha8(const std::shared_ptr<ArrayBuffer>& input,
                                                          const std::shared_ptr<ArrayBuffer>& key,
                                                          const std::shared_ptr<ArrayBuffer>& iv) {
  if (!input || !key || !iv) throw std::invalid_argument("Input, key and IV must not be null");
  if (key->size() != CHACHA_KEY_SIZE) throw std::invalid_argument("Key must be exactly 32 bytes");
  if (iv->size() != CHACHA_IV_SIZE) throw std::invalid_argument("IV must be exactly 8 bytes");

  // Allocate output buffer
  std::vector<uint8_t> output(input->size());

  // Call the modern ChaCha8 XOR function
  chacha8_xor(static_cast<const uint8_t*>(input->data()),  // input data
              input->size(),                               // input length
              static_cast<const uint8_t*>(key->data()),    // key
              static_cast<const uint8_t*>(iv->data()),     // iv
              output.data()                                // output
  );

  return ArrayBuffer::copy(output);
}

/**
 * Real ChaCha12 encryption using Conceal Core implementation.
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::chacha12(
    const std::shared_ptr<ArrayBuffer>& input, const std::shared_ptr<ArrayBuffer>& key,
    const std::shared_ptr<ArrayBuffer>& iv) {
  if (!input || !key || !iv) throw std::invalid_argument("Input, key and IV must not be null");
  if (key->size() != CHACHA_KEY_SIZE) throw std::invalid_argument("Key must be exactly 32 bytes");
  if (iv->size() != CHACHA_IV_SIZE) throw std::invalid_argument("IV must be exactly 8 bytes");

  // Allocate output buffer
  std::vector<uint8_t> output(input->size());

  // Call the modern ChaCha12 XOR function
  chacha12_xor(static_cast<const uint8_t*>(input->data()),  // input data
               input->size(),                               // input length
               static_cast<const uint8_t*>(key->data()),    // key
               static_cast<const uint8_t*>(iv->data()),     // iv
               output.data()                                // output
  );

  return ArrayBuffer::copy(output);
}

std::shared_ptr<ArrayBuffer> HybridConcealCrypto::hmacSha1(
    const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) {
  return Hmac::hmacSha1(key, data);
}

std::shared_ptr<ArrayBuffer> HybridConcealCrypto::hmacSha256(
    const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) {
  return Hmac::hmacSha256(key, data);
}

std::shared_ptr<ArrayBuffer> HybridConcealCrypto::hmacSha512(
    const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) {
  return Hmac::hmacSha512(key, data);
}

/**
 * Clean JavaScript API for mnemonic-style random generation
 */
std::string HybridConcealCrypto::random(double bits) { return ::mn_random(bits); }

/**
 * Clean JavaScript API for random bytes generation
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::randomBytes(double bytes) {
  std::vector<uint8_t> random_data = ::mn_random_bytes(bytes);
  return ArrayBuffer::copy(random_data);
}

/**
 * libsodium secretbox encryption (authenticated encryption)
 */
std::shared_ptr<ArrayBuffer> HybridConcealCrypto::secretbox(
    const std::shared_ptr<ArrayBuffer>& message, const std::shared_ptr<ArrayBuffer>& nonce,
    const std::shared_ptr<ArrayBuffer>& key) {
  if (!message || !nonce || !key)
    throw std::invalid_argument("Message, nonce and key must not be null");
  if (nonce->size() != crypto_secretbox_NONCEBYTES)
    throw std::invalid_argument("Invalid nonce size");
  if (key->size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("Invalid key size");

  size_t cipher_len = message->size() + crypto_secretbox_MACBYTES;
  std::vector<uint8_t> ciphertext(cipher_len);

  int result =
      crypto_secretbox_easy(ciphertext.data(), static_cast<const unsigned char*>(message->data()),
                            message->size(), static_cast<const unsigned char*>(nonce->data()),
                            static_cast<const unsigned char*>(key->data()));

  if (result != 0) throw std::runtime_error("Secretbox encryption failed");

  return ArrayBuffer::copy(ciphertext);
}

/**
 * libsodium secretbox decryption (authenticated decryption)
 * Returns std::nullopt if authentication/decryption fails
 */
std::optional<std::shared_ptr<ArrayBuffer>> HybridConcealCrypto::secretboxOpen(
    const std::shared_ptr<ArrayBuffer>& ciphertext, const std::shared_ptr<ArrayBuffer>& nonce,
    const std::shared_ptr<ArrayBuffer>& key) {
  if (!ciphertext || !nonce || !key)
    throw std::invalid_argument("Ciphertext, nonce and key must not be null");
  if (ciphertext->size() < crypto_secretbox_MACBYTES)
    throw std::invalid_argument("Ciphertext too short");
  if (nonce->size() != crypto_secretbox_NONCEBYTES)
    throw std::invalid_argument("Invalid nonce size");
  if (key->size() != crypto_secretbox_KEYBYTES) throw std::invalid_argument("Invalid key size");

  size_t message_len = ciphertext->size() - crypto_secretbox_MACBYTES;
  std::vector<uint8_t> message(message_len);

  int result = crypto_secretbox_open_easy(
      message.data(), static_cast<const unsigned char*>(ciphertext->data()), ciphertext->size(),
      static_cast<const unsigned char*>(nonce->data()),
      static_cast<const unsigned char*>(key->data()));

  if (result != 0) return std::nullopt;  // Authentication failed

  return ArrayBuffer::copy(message);
}

/**
 * Argon2id v0x13 key derivation (32-byte key), validated on the JS thread, derived off-thread.
 * This method never throws: every failure rejects the returned promise (wrong JS argument types
 * are thrown earlier by Nitro's argument conversion).
 */
std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridConcealCrypto::argon2id(
    const std::shared_ptr<ArrayBuffer>& password, const std::shared_ptr<ArrayBuffer>& salt,
    double memoryKiB, double iterations, double parallelism) {
  using KeyPromise = Promise<std::shared_ptr<ArrayBuffer>>;
  auto reject = [](const char* message) {
    return KeyPromise::rejected(std::make_exception_ptr(std::invalid_argument(message)));
  };
  auto isUint32 = [](double x) {
    return std::isfinite(x) && std::floor(x) == x && x >= 0 && x <= UINT32_MAX;
  };

  if (!password || !salt) return reject("argon2id: password and salt must not be null");
  if (!isUint32(memoryKiB)) return reject("argon2id: memoryKiB must be an integer");
  if (!isUint32(iterations)) return reject("argon2id: iterations must be an integer");
  if (!isUint32(parallelism)) return reject("argon2id: parallelism must be an integer");
  const auto m = static_cast<uint32_t>(memoryKiB);
  const auto t = static_cast<uint32_t>(iterations);
  const auto p = static_cast<uint32_t>(parallelism);

  switch (argon2id_check(password->size(), salt->size(), m, t, p)) {
    case ARGON2ID_OK:
      break;
    case ARGON2ID_ERR_PASSWORD:
      return reject("argon2id: password must be at most 1024 bytes");
    case ARGON2ID_ERR_SALT:
      return reject("argon2id: salt must be 16 bytes (other lengths not supported)");
    case ARGON2ID_ERR_PARALLELISM:
      return reject("argon2id: parallelism must be 1 (other values not supported)");
    case ARGON2ID_ERR_ITERATIONS:
      return reject("argon2id: iterations must be 1 to 64");
    case ARGON2ID_ERR_MEMORY:
      return reject("argon2id: memoryKiB must be 8 to 65536");
    default:
      return KeyPromise::rejected(std::make_exception_ptr(std::runtime_error("argon2id: failed")));
  }

  // JS-owned buffers expire when this call returns; the worker needs its own copies.
  auto copyBytes = [](const std::shared_ptr<ArrayBuffer>& buffer) {
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    if (buffer->size() > 0) {
      const uint8_t* data = static_cast<const uint8_t*>(buffer->data());
      bytes->assign(data, data + buffer->size());
    }
    return bytes;
  };
  auto pw = copyBytes(password);
  auto saltBytes = copyBytes(salt);

  return KeyPromise::async([pw, saltBytes, m, t, p]() -> std::shared_ptr<ArrayBuffer> {
    static std::mutex argon2idMutex;
    std::lock_guard<std::mutex> lock(argon2idMutex);

    uint8_t key[ARGON2ID_KEY_SIZE];
    struct KeyWipe {
      uint8_t* bytes;
      ~KeyWipe() { sodium_memzero(bytes, ARGON2ID_KEY_SIZE); }
    } keyWipe{key};
    int rc =
        argon2id_derive(pw->data(), pw->size(), saltBytes->data(), saltBytes->size(), m, t, p, key);
    if (!pw->empty()) sodium_memzero(pw->data(), pw->size());
    if (rc != ARGON2ID_OK) throw std::runtime_error("argon2id: derivation failed");

    return ArrayBuffer::copy(key, ARGON2ID_KEY_SIZE);
  });
}

/**
 * Get the Cryptonote sub-object for elliptic curve operations
 */
std::shared_ptr<HybridCryptonoteSpec> HybridConcealCrypto::getCryptonote() { return _cryptonote; }

/**
 * Get the Mnemonics sub-object for mnemonic encoding/decoding operations
 */
std::shared_ptr<HybridMnemonicsSpec> HybridConcealCrypto::getMnemonics() { return _mnemonics; }

/**
 * Get the Cypher sub-object for IETF ChaCha operations
 */
std::shared_ptr<HybridCypherSpec> HybridConcealCrypto::getCypher() { return _cypher; }