/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#pragma once
#include <NitroModules/ArrayBuffer.hpp>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace margelo::nitro::concealcrypto {

/**
 * HMAC-SHA1/SHA-256/SHA-512 implementations following RFC 2104 / RFC 4231 / FIPS 180-4
 * Used for TOTP computation and other cryptographic operations
 */
class Hmac {
 public:
  /**
   * Compute HMAC-SHA1 of data using the provided key (RFC 2104, FIPS 198-1)
   * @param key The secret key as ArrayBuffer
   * @param data The message data as ArrayBuffer
   * @return HMAC-SHA1 result as ArrayBuffer (20 bytes)
   */
  static std::shared_ptr<ArrayBuffer> hmacSha1(const std::shared_ptr<ArrayBuffer>& key,
                                               const std::shared_ptr<ArrayBuffer>& data);

  /**
   * Compute HMAC-SHA256 of data using the provided key (RFC 2104, FIPS 180-4)
   * @param key The secret key as ArrayBuffer
   * @param data The message data as ArrayBuffer
   * @return HMAC-SHA256 result as ArrayBuffer (32 bytes)
   */
  static std::shared_ptr<ArrayBuffer> hmacSha256(const std::shared_ptr<ArrayBuffer>& key,
                                                 const std::shared_ptr<ArrayBuffer>& data);

  /**
   * Compute HMAC-SHA512 of data using the provided key (RFC 2104, FIPS 180-4)
   * @param key The secret key as ArrayBuffer
   * @param data The message data as ArrayBuffer
   * @return HMAC-SHA512 result as ArrayBuffer (64 bytes)
   */
  static std::shared_ptr<ArrayBuffer> hmacSha512(const std::shared_ptr<ArrayBuffer>& key,
                                                 const std::shared_ptr<ArrayBuffer>& data);

 private:
  // Performance optimization: pre-allocated thread-local buffers to reduce heap allocations
  // Since HMAC is called frequently (e.g., TOTP every 30s, transaction signing), this reduces
  // overhead
  struct HmacBuffers {
    std::vector<uint8_t> innerPadded;
    std::vector<uint8_t> outerPadded;
    std::vector<uint8_t> innerData;
    std::vector<uint8_t> outerData;
  };
  static thread_local HmacBuffers buffers;

 private:
  /**
   * SHA-1 hash function (FIPS 180-4, Section 6.1)
   * @return 20-byte digest
   */
  static std::vector<uint8_t> sha1(const std::vector<uint8_t>& data);

  /**
   * SHA-256 hash function (FIPS 180-4, Section 6.2)
   * @return 32-byte digest
   */
  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

  /**
   * SHA-512 hash function (FIPS 180-4, Section 6.4)
   * @return 64-byte digest
   */
  static std::vector<uint8_t> sha512(const std::vector<uint8_t>& data);

  /**
   * Generic RFC 2104 HMAC core — shared by hmacSha1 / hmacSha256 / hmacSha512.
   * @param hashFn     The underlying hash function (sha1 / sha256 / sha512)
   * @param blockSize  Hash function block size in bytes (64 for SHA-1/256, 128 for SHA-512)
   */
  template <typename HashFunc>
  static std::shared_ptr<ArrayBuffer> hmacImpl(HashFunc&& hashFn, size_t blockSize,
                                               const std::shared_ptr<ArrayBuffer>& key,
                                               const std::shared_ptr<ArrayBuffer>& data) {
    if (!key || !data) {
      throw std::invalid_argument("Key and data must not be null");
    }

    std::vector<uint8_t> keyBytes = arrayBufferToVector(key);
    std::vector<uint8_t> dataBytes = arrayBufferToVector(data);

    // Step 1: Normalise key to exactly blockSize bytes (RFC 2104 §2)
    if (keyBytes.size() > blockSize) {
      keyBytes = hashFn(keyBytes);
    }
    if (keyBytes.size() < blockSize) {
      keyBytes.resize(blockSize, 0);
    }

    // Step 2: Build ipad / opad keys — reuse thread-local buffers to avoid heap churn
    buffers.innerPadded.resize(blockSize);
    buffers.outerPadded.resize(blockSize);
    for (size_t i = 0; i < blockSize; i++) {
      buffers.innerPadded[i] = keyBytes[i] ^ 0x36;
      buffers.outerPadded[i] = keyBytes[i] ^ 0x5c;
    }

    // Step 3: inner hash — H(ipad || data)
    buffers.innerData.resize(blockSize + dataBytes.size());
    std::memcpy(buffers.innerData.data(), buffers.innerPadded.data(), blockSize);
    std::memcpy(buffers.innerData.data() + blockSize, dataBytes.data(), dataBytes.size());
    std::vector<uint8_t> innerHash = hashFn(buffers.innerData);

    // Step 4: outer hash — H(opad || innerHash)
    buffers.outerData.resize(blockSize + innerHash.size());
    std::memcpy(buffers.outerData.data(), buffers.outerPadded.data(), blockSize);
    std::memcpy(buffers.outerData.data() + blockSize, innerHash.data(), innerHash.size());

    return vectorToArrayBuffer(hashFn(buffers.outerData));
  }

  static constexpr uint32_t leftRotate(uint32_t value, int amount) noexcept;
  static constexpr uint32_t rightRotate32(uint32_t value, int amount) noexcept;
  static constexpr uint64_t rightRotate64(uint64_t value, int amount) noexcept;

  static std::vector<uint8_t> arrayBufferToVector(const std::shared_ptr<ArrayBuffer>& buffer);
  static std::shared_ptr<ArrayBuffer> vectorToArrayBuffer(const std::vector<uint8_t>& data);
};

}  // namespace margelo::nitro::concealcrypto
