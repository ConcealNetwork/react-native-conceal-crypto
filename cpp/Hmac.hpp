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
#include <memory>
#include <string>
#include <vector>

namespace margelo::nitro::concealcrypto {

/**
 * HMAC-SHA1 implementation following RFC 2104 and FIPS 198-1
 * Used for TOTP computation and other cryptographic operations
 */
class Hmac {
 public:
  /**
   * Compute HMAC-SHA1 of data using the provided key
   * @param key The secret key as ArrayBuffer
   * @param data The message data as ArrayBuffer
   * @return HMAC-SHA1 result as ArrayBuffer (20 bytes)
   */
  static std::shared_ptr<ArrayBuffer> hmacSha1(const std::shared_ptr<ArrayBuffer>& key,
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
   * SHA-1 hash function implementation
   * @param data Input data to hash
   * @return SHA-1 hash as vector of bytes (20 bytes)
   */
  static std::vector<uint8_t> sha1(const std::vector<uint8_t>& data);

  /**
   * Left rotate operation for SHA-1
   * @param value Value to rotate
   * @param amount Number of bits to rotate left
   * @return Rotated value
   */
  static constexpr uint32_t leftRotate(uint32_t value, int amount) noexcept;

  /**
   * Convert ArrayBuffer to vector of bytes
   * @param buffer Input ArrayBuffer
   * @return Vector of bytes
   */
  static std::vector<uint8_t> arrayBufferToVector(const std::shared_ptr<ArrayBuffer>& buffer);

  /**
   * Convert vector of bytes to ArrayBuffer
   * @param data Vector of bytes
   * @return ArrayBuffer
   */
  static std::shared_ptr<ArrayBuffer> vectorToArrayBuffer(const std::vector<uint8_t>& data);
};

}  // namespace margelo::nitro::concealcrypto
