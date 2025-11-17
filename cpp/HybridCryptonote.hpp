/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#pragma once

#include <array>
#include <memory>

#include "../nitrogen/generated/shared/c++/HybridCryptonoteSpec.hpp"

namespace margelo::nitro::concealcrypto {

using namespace margelo::nitro;

// Compile-time constants for optimization
constexpr size_t CRYPTONOTE_KEY_SIZE = 32;
constexpr size_t CRYPTONOTE_POINT_SIZE = 32;
constexpr size_t CRYPTONOTE_DERIVATION_SIZE = 32;

// Maximum varint size for 64-bit integer: ceil(64 / 7) = 10 bytes
constexpr size_t MAX_VARINT_SIZE = (sizeof(uint64_t) * 8 + 6) / 7;

// Pre-allocated static buffers for frequently used operations
class CryptonoteBuffers {
 public:
  // Static thread-local buffers to avoid repeated allocations
  static thread_local std::array<uint8_t, CRYPTONOTE_KEY_SIZE> key_buffer_1;
  static thread_local std::array<uint8_t, CRYPTONOTE_KEY_SIZE> key_buffer_2;
  static thread_local std::array<uint8_t, CRYPTONOTE_DERIVATION_SIZE> derivation_buffer;
  static thread_local std::array<uint8_t, CRYPTONOTE_POINT_SIZE> point_buffer_1;
  static thread_local std::array<uint8_t, CRYPTONOTE_POINT_SIZE> point_buffer_2;
  static thread_local std::array<uint8_t, CRYPTONOTE_POINT_SIZE> result_buffer;
};

// Optimized inline helper functions
namespace cryptonote_utils {
// Fast hex to bytes conversion (optimized for 32-byte keys)
inline bool hextobin(const std::string& hex, uint8_t* out, size_t expected_size) noexcept {
  if (hex.length() != expected_size * 2) return false;

  for (size_t i = 0; i < expected_size; ++i) {
    char high = hex[i * 2];
    char low = hex[i * 2 + 1];

    // Fast hex digit conversion
    uint8_t h = (high >= '0' && high <= '9')   ? (high - '0')
                : (high >= 'a' && high <= 'f') ? (high - 'a' + 10)
                : (high >= 'A' && high <= 'F') ? (high - 'A' + 10)
                                               : 0xFF;
    uint8_t l = (low >= '0' && low <= '9')   ? (low - '0')
                : (low >= 'a' && low <= 'f') ? (low - 'a' + 10)
                : (low >= 'A' && low <= 'F') ? (low - 'A' + 10)
                                             : 0xFF;

    if (h == 0xFF || l == 0xFF) return false;
    out[i] = (h << 4) | l;
  }
  return true;
}

// Fast bytes to hex conversion
inline std::string bintohex(const uint8_t* data, size_t size) noexcept {
  static const char hex_chars[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2);

  for (size_t i = 0; i < size; ++i) {
    result += hex_chars[(data[i] >> 4) & 0x0F];
    result += hex_chars[data[i] & 0x0F];
  }
  return result;
}

// Validate hex string length
inline constexpr bool isValidHexSize(size_t hex_len, size_t expected_bytes) noexcept {
  return hex_len == expected_bytes * 2;
}
}  // namespace cryptonote_utils

class HybridCryptonote : public HybridCryptonoteSpec {
 public:
  HybridCryptonote();

  // Optimized Cryptonote elliptic curve operations
  // Using hex strings for inputs to minimize JSI overhead (<100 byte payloads)
  // Following Nitro's performance guidelines

  std::string generateKeyDerivation(const std::string& publicKeyHex,
                                    const std::string& secretKeyHex) override;

  std::string derivePublicKey(const std::string& derivationHex, double outputIndex,
                              const std::string& publicKeyHex) override;

  std::string geScalarmult(const std::string& publicKeyHex,
                           const std::string& secretKeyHex) override;

  std::string geAdd(const std::string& point1Hex, const std::string& point2Hex) override;

  std::string geScalarmultBase(const std::string& secretKeyHex) override;

  std::string geDoubleScalarmultBaseVartime(const std::string& cHex, const std::string& PHex,
                                            const std::string& rHex) override;

  std::string geDoubleScalarmultPostcompVartime(const std::string& rHex, const std::string& PHex,
                                                const std::string& cHex,
                                                const std::string& IHex) override;

  std::string cnFastHash(const std::string& inputHex) override;

  std::string encodeVarint(double value) override;

  std::vector<std::string> generateRingSignature(const std::string& prefixHashHex,
                                                 const std::string& keyImageHex,
                                                 const std::vector<std::string>& publicKeysHex,
                                                 const std::string& secretKeyHex,
                                                 double secretIndex) override;

 private:
  // Fast validation for hex strings
  inline bool validateHexInput(const std::string& hex) const noexcept {
    return cryptonote_utils::isValidHexSize(hex.length(), CRYPTONOTE_KEY_SIZE);
  }
};

}  // namespace margelo::nitro::concealcrypto
