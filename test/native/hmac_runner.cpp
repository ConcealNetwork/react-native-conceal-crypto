/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

/*
 * Standalone runner for the hand-rolled HMAC (no Nitro / RN host needed).
 * Usage: hmac_runner <sha1|sha256|sha512> <key-hex> <data-hex>
 * Prints the lowercase hex digest on stdout.
 * Exit 0 on success, 1 on invalid input, 64 on usage error.
 *
 * Correctness oracle: RFC 2202 section 3 (HMAC-SHA-1) and RFC 4231
 * sections 4.2-4.8 (HMAC-SHA-256 / HMAC-SHA-512) test vectors.
 */

#include <NitroModules/ArrayBuffer.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "Hmac.hpp"

namespace {

using margelo::nitro::ArrayBuffer;
using margelo::nitro::concealcrypto::Hmac;

constexpr int EXIT_OK = 0;
constexpr int EXIT_INVALID = 1;
constexpr int EXIT_USAGE = 64;

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse_hex(const std::string &hex, std::vector<uint8_t> &out) {
  if (hex.size() % 2 != 0) return false;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = hex_nibble(hex[i]);
    int lo = hex_nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

std::string buffer_to_hex(const std::shared_ptr<ArrayBuffer> &buffer) {
  static const char *digits = "0123456789abcdef";
  const uint8_t *data = static_cast<const uint8_t *>(buffer->data());
  std::string out(buffer->size() * 2, '0');
  for (size_t i = 0; i < buffer->size(); i++) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 0xf];
  }
  return out;
}

std::shared_ptr<ArrayBuffer> vector_to_buffer(const std::vector<uint8_t> &bytes) {
  if (bytes.empty()) return ArrayBuffer::allocate(0);
  return ArrayBuffer::copy(bytes);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 4) {
    std::fprintf(stderr, "usage: %s <sha1|sha256|sha512> <key-hex> <data-hex>\n", argv[0]);
    return EXIT_USAGE;
  }

  const std::string algo = argv[1];
  if (algo != "sha1" && algo != "sha256" && algo != "sha512") return EXIT_USAGE;

  std::vector<uint8_t> keyBytes;
  std::vector<uint8_t> dataBytes;
  if (!parse_hex(argv[2], keyBytes) || !parse_hex(argv[3], dataBytes)) return EXIT_INVALID;

  std::shared_ptr<ArrayBuffer> key = vector_to_buffer(keyBytes);
  std::shared_ptr<ArrayBuffer> data = vector_to_buffer(dataBytes);

  std::shared_ptr<ArrayBuffer> digest;
  try {
    if (algo == "sha1") {
      digest = Hmac::hmacSha1(key, data);
    } else if (algo == "sha256") {
      digest = Hmac::hmacSha256(key, data);
    } else {
      digest = Hmac::hmacSha512(key, data);
    }
  } catch (const std::exception &) {
    return EXIT_INVALID;
  }

  std::printf("%s\n", buffer_to_hex(digest).c_str());
  return EXIT_OK;
}
