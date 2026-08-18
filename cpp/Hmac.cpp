/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * code as per implenetation RFC2104 / RFC4231 / FIPS 180-4
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include "Hmac.hpp"

#include <stdexcept>

namespace margelo::nitro::concealcrypto {

// Initialize thread-local buffers
thread_local Hmac::HmacBuffers Hmac::buffers;

std::shared_ptr<ArrayBuffer> Hmac::hmacSha1(const std::shared_ptr<ArrayBuffer>& key,
                                            const std::shared_ptr<ArrayBuffer>& data) {
  return hmacImpl([](const std::vector<uint8_t>& d) { return sha1(d); }, 64, key, data);
}

std::shared_ptr<ArrayBuffer> Hmac::hmacSha256(const std::shared_ptr<ArrayBuffer>& key,
                                              const std::shared_ptr<ArrayBuffer>& data) {
  return hmacImpl([](const std::vector<uint8_t>& d) { return sha256(d); }, 64, key, data);
}

std::shared_ptr<ArrayBuffer> Hmac::hmacSha512(const std::shared_ptr<ArrayBuffer>& key,
                                              const std::shared_ptr<ArrayBuffer>& data) {
  return hmacImpl([](const std::vector<uint8_t>& d) { return sha512(d); }, 128, key, data);
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

std::vector<uint8_t> Hmac::sha256(const std::vector<uint8_t>& data) {
  // Initial hash values — first 32 bits of fractional parts of sqrt of first 8 primes
  // (FIPS 180-4, Section 5.3.3)
  constexpr uint32_t h_init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  // Round constants — first 32 bits of fractional parts of cbrt of first 64 primes
  // (FIPS 180-4, Section 4.2.2)
  constexpr uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};

  uint32_t h[8];
  std::memcpy(h, h_init, sizeof(h));

  size_t msgLength = data.size();
  uint64_t bitLength = static_cast<uint64_t>(msgLength) * 8;

  std::vector<uint8_t> padded;
  padded.reserve(((msgLength + 9 + 63) / 64) * 64);
  padded.insert(padded.end(), data.begin(), data.end());
  padded.push_back(0x80);
  while (padded.size() % 64 != 56) {
    padded.push_back(0);
  }
  for (int i = 7; i >= 0; i--) {
    padded.push_back((bitLength >> (i * 8)) & 0xFF);
  }

  for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
      w[i] = (static_cast<uint32_t>(padded[chunk + i * 4]) << 24) |
             (static_cast<uint32_t>(padded[chunk + i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(padded[chunk + i * 4 + 2]) << 8) |
             static_cast<uint32_t>(padded[chunk + i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = rightRotate32(w[i - 15], 7) ^ rightRotate32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = rightRotate32(w[i - 2], 17) ^ rightRotate32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h7 = h[7];

    for (int i = 0; i < 64; i++) {
      uint32_t S1 = rightRotate32(e, 6) ^ rightRotate32(e, 11) ^ rightRotate32(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t temp1 = h7 + S1 + ch + k[i] + w[i];
      uint32_t S0 = rightRotate32(a, 2) ^ rightRotate32(a, 13) ^ rightRotate32(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;
      h7 = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += h7;
  }

  std::vector<uint8_t> result(32);
  for (int i = 0; i < 8; i++) {
    result[i * 4] = (h[i] >> 24) & 0xFF;
    result[i * 4 + 1] = (h[i] >> 16) & 0xFF;
    result[i * 4 + 2] = (h[i] >> 8) & 0xFF;
    result[i * 4 + 3] = h[i] & 0xFF;
  }
  return result;
}

std::vector<uint8_t> Hmac::sha512(const std::vector<uint8_t>& data) {
  // Initial hash values — first 64 bits of fractional parts of sqrt of first 8 primes
  // (FIPS 180-4, Section 5.3.5)
  constexpr uint64_t h_init[8] = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
      0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

  // Round constants — first 64 bits of fractional parts of cbrt of first 80 primes
  // (FIPS 180-4, Section 4.2.3)
  constexpr uint64_t k[80] = {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
      0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
      0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
      0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
      0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
      0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
      0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
      0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
      0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
      0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
      0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
      0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
      0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
      0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

  uint64_t h[8];
  std::memcpy(h, h_init, sizeof(h));

  size_t msgLength = data.size();
  uint64_t bitLength = static_cast<uint64_t>(msgLength) * 8;

  // SHA-512 pads to 896 mod 1024 bits, i.e. 112 mod 128 bytes
  std::vector<uint8_t> padded;
  padded.reserve(((msgLength + 17 + 127) / 128) * 128);
  padded.insert(padded.end(), data.begin(), data.end());
  padded.push_back(0x80);
  while (padded.size() % 128 != 112) {
    padded.push_back(0);
  }
  // Append 128-bit big-endian length; high 64 bits are always 0 for practical message sizes
  for (int i = 0; i < 8; i++) {
    padded.push_back(0);
  }
  for (int i = 7; i >= 0; i--) {
    padded.push_back((bitLength >> (i * 8)) & 0xFF);
  }

  for (size_t chunk = 0; chunk < padded.size(); chunk += 128) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
      w[i] = (static_cast<uint64_t>(padded[chunk + i * 8]) << 56) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 1]) << 48) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 2]) << 40) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 3]) << 32) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 4]) << 24) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 5]) << 16) |
             (static_cast<uint64_t>(padded[chunk + i * 8 + 6]) << 8) |
             static_cast<uint64_t>(padded[chunk + i * 8 + 7]);
    }
    for (int i = 16; i < 80; i++) {
      uint64_t s0 = rightRotate64(w[i - 15], 1) ^ rightRotate64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      uint64_t s1 = rightRotate64(w[i - 2], 19) ^ rightRotate64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], h7 = h[7];

    for (int i = 0; i < 80; i++) {
      uint64_t S1 = rightRotate64(e, 14) ^ rightRotate64(e, 18) ^ rightRotate64(e, 41);
      uint64_t ch = (e & f) ^ (~e & g);
      uint64_t temp1 = h7 + S1 + ch + k[i] + w[i];
      uint64_t S0 = rightRotate64(a, 28) ^ rightRotate64(a, 34) ^ rightRotate64(a, 39);
      uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint64_t temp2 = S0 + maj;
      h7 = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += h7;
  }

  std::vector<uint8_t> result(64);
  for (int i = 0; i < 8; i++) {
    result[i * 8] = (h[i] >> 56) & 0xFF;
    result[i * 8 + 1] = (h[i] >> 48) & 0xFF;
    result[i * 8 + 2] = (h[i] >> 40) & 0xFF;
    result[i * 8 + 3] = (h[i] >> 32) & 0xFF;
    result[i * 8 + 4] = (h[i] >> 24) & 0xFF;
    result[i * 8 + 5] = (h[i] >> 16) & 0xFF;
    result[i * 8 + 6] = (h[i] >> 8) & 0xFF;
    result[i * 8 + 7] = h[i] & 0xFF;
  }
  return result;
}

constexpr uint32_t Hmac::leftRotate(uint32_t value, int amount) noexcept {
  amount &= 31;
  return (value << amount) | (value >> (32 - amount));
}

constexpr uint32_t Hmac::rightRotate32(uint32_t value, int amount) noexcept {
  amount &= 31;
  return (value >> amount) | (value << (32 - amount));
}

constexpr uint64_t Hmac::rightRotate64(uint64_t value, int amount) noexcept {
  amount &= 63;
  return (value >> amount) | (value << (64 - amount));
}

std::vector<uint8_t> Hmac::arrayBufferToVector(const std::shared_ptr<ArrayBuffer>& buffer) {
  if (!buffer) {
    throw std::invalid_argument("Buffer must not be null");
  }

  if (buffer->size() == 0) {
    return std::vector<uint8_t>();
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