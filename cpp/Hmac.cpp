/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include "Hmac.hpp"

#include <cstring>
#include <stdexcept>

namespace margelo::nitro::concealcrypto {

// Initialize thread-local buffers
thread_local Hmac::HmacBuffers Hmac::buffers;

std::shared_ptr<ArrayBuffer> Hmac::hmacSha1(const std::shared_ptr<ArrayBuffer>& key,
                                            const std::shared_ptr<ArrayBuffer>& data) {
  if (!key || !data) {
    throw std::invalid_argument("Key and data must not be null");
  }

  // Convert ArrayBuffers to vectors for easier manipulation
  std::vector<uint8_t> keyBytes = arrayBufferToVector(key);
  std::vector<uint8_t> dataBytes = arrayBufferToVector(data);

  // HMAC-SHA1 implementation following RFC 2104
  constexpr size_t blockSize = 64;  // SHA-1 block size

  // Step 1: Prepare the key
  if (keyBytes.size() > blockSize) {
    keyBytes = sha1(keyBytes);
  }

  if (keyBytes.size() < blockSize) {
    keyBytes.resize(blockSize, 0);
  }

  // Step 2: Create inner and outer padded keys (reuse thread-local buffers for performance)
  buffers.innerPadded.resize(blockSize);
  buffers.outerPadded.resize(blockSize);

  for (size_t i = 0; i < blockSize; i++) {
    buffers.innerPadded[i] = keyBytes[i] ^ 0x36;
    buffers.outerPadded[i] = keyBytes[i] ^ 0x5c;
  }

  // Step 3: Calculate inner hash: SHA1(innerPadded || data)
  buffers.innerData.resize(blockSize + dataBytes.size());
  std::memcpy(buffers.innerData.data(), buffers.innerPadded.data(), blockSize);
  std::memcpy(buffers.innerData.data() + blockSize, dataBytes.data(), dataBytes.size());

  std::vector<uint8_t> innerHash = sha1(buffers.innerData);

  // Step 4: Calculate outer hash: SHA1(outerPadded || innerHash)
  buffers.outerData.resize(blockSize + innerHash.size());
  std::memcpy(buffers.outerData.data(), buffers.outerPadded.data(), blockSize);
  std::memcpy(buffers.outerData.data() + blockSize, innerHash.data(), innerHash.size());

  return vectorToArrayBuffer(sha1(buffers.outerData));
}

std::vector<uint8_t> Hmac::sha1(const std::vector<uint8_t>& data) {
  // Initialize hash values (h0, h1, h2, h3, h4) - constexpr for compile-time optimization
  constexpr uint32_t h0_init = 0x67452301;
  constexpr uint32_t h1_init = 0xEFCDAB89;
  constexpr uint32_t h2_init = 0x98BADCFE;
  constexpr uint32_t h3_init = 0x10325476;
  constexpr uint32_t h4_init = 0xC3D2E1F0;

  // SHA-1 constants - constexpr for compile-time optimization
  constexpr uint32_t k1 = 0x5A827999;
  constexpr uint32_t k2 = 0x6ED9EBA1;
  constexpr uint32_t k3 = 0x8F1BBCDC;
  constexpr uint32_t k4 = 0xCA62C1D6;

  uint32_t h[5] = {h0_init, h1_init, h2_init, h3_init, h4_init};

  // Pre-processing
  size_t msgLength = data.size();
  uint64_t bitLength = msgLength * 8;

  std::vector<uint8_t> padded;
  padded.reserve(((msgLength + 9) / 64 + 1) * 64);
  padded.insert(padded.end(), data.begin(), data.end());
  padded.push_back(0x80);

  while ((padded.size() * 8) % 512 != 448) {
    padded.push_back(0);
  }

  for (int i = 7; i >= 0; i--) {
    padded.push_back((bitLength >> (i * 8)) & 0xFF);
  }

  // Process in 512-bit chunks
  for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
    uint32_t w[80];

    for (int i = 0; i < 16; i++) {
      w[i] = (static_cast<uint32_t>(padded[chunk + i * 4]) << 24) |
             (static_cast<uint32_t>(padded[chunk + i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(padded[chunk + i * 4 + 2]) << 8) |
             static_cast<uint32_t>(padded[chunk + i * 4 + 3]);
    }

    for (int i = 16; i < 80; i++) {
      w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    for (int i = 0; i < 80; i++) {
      uint32_t f, k;

      if (i < 20) {
        f = (b & c) | (~b & d);
        k = k1;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = k2;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = k3;
      } else {
        f = b ^ c ^ d;
        k = k4;
      }

      uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = leftRotate(b, 30);
      b = a;
      a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  // Convert to bytes
  std::vector<uint8_t> result(20);
  for (int i = 0; i < 5; i++) {
    result[i * 4] = (h[i] >> 24) & 0xFF;
    result[i * 4 + 1] = (h[i] >> 16) & 0xFF;
    result[i * 4 + 2] = (h[i] >> 8) & 0xFF;
    result[i * 4 + 3] = h[i] & 0xFF;
  }

  return result;
}

constexpr uint32_t Hmac::leftRotate(uint32_t value, int amount) noexcept {
  return (value << amount) | (value >> (32 - amount));
}

std::vector<uint8_t> Hmac::arrayBufferToVector(const std::shared_ptr<ArrayBuffer>& buffer) {
  if (!buffer) {
    throw std::invalid_argument("Buffer must not be null");
  }

  const uint8_t* data = static_cast<const uint8_t*>(buffer->data());
  return std::vector<uint8_t>(data, data + buffer->size());
}

std::shared_ptr<ArrayBuffer> Hmac::vectorToArrayBuffer(const std::vector<uint8_t>& data) {
  if (data.empty()) {
    return ArrayBuffer::allocate(0);
  }

  return ArrayBuffer::copy(data);
}

}  // namespace margelo::nitro::concealcrypto