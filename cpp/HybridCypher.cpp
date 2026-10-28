/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include "HybridCypher.hpp"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "chacha.h"

using namespace margelo::nitro;
using namespace margelo::nitro::concealcrypto;

// TAG constant for HybridObject registration
constexpr auto TAG = "Cypher";

/**
 * Constructor — must call HybridObject(TAG) base constructor.
 */
HybridCypher::HybridCypher() : HybridObject(TAG) {}

/**
 * Maps a CHACHA_ERR_* code to the matching C++ exception.
 */
static void throwOnError(int rc, int rounds) {
  if (rc == CHACHA_OK) return;
  const std::string name = "chacha" + std::to_string(rounds);
  switch (rc) {
    case CHACHA_ERR_KEY:
      throw std::invalid_argument(name + ": key must be 32 bytes");
    case CHACHA_ERR_NONCE:
      throw std::invalid_argument(name + ": nonce must be 12 bytes");
    case CHACHA_ERR_ROUNDS:
      throw std::invalid_argument(name + ": rounds must be 8, 12 or 20");
    case CHACHA_ERR_LENGTH:
      throw std::range_error(name + ": data too long");
    default:
      throw std::runtime_error(name + ": failed");
  }
}

/**
 * Shared IETF ChaCha XOR for all round counts.
 */
std::shared_ptr<ArrayBuffer> HybridCypher::chacha(const std::shared_ptr<ArrayBuffer>& key,
                                                  const std::shared_ptr<ArrayBuffer>& nonce,
                                                  const std::shared_ptr<ArrayBuffer>& data,
                                                  int rounds) {
  if (!key || !nonce || !data)
    throw std::invalid_argument("chacha" + std::to_string(rounds) +
                                ": key, nonce and data must not be null");
  throwOnError(chacha_ietf_check(data->size(), key->size(), nonce->size(), rounds), rounds);
  if (data->size() == 0) return ArrayBuffer::allocate(0);

  // chacha_block reads key/nonce as uint32_t words
  alignas(uint32_t) uint8_t k[CHACHA_KEY_SIZE];
  alignas(uint32_t) uint8_t n[CHACHA_NONCE_SIZE];
  std::memcpy(k, key->data(), sizeof(k));
  std::memcpy(n, nonce->data(), sizeof(n));

  std::vector<uint8_t> output(data->size());
  int rc = chacha_ietf_xor(static_cast<const uint8_t*>(data->data()), data->size(), k, sizeof(k), n,
                           sizeof(n), rounds, output.data());
  throwOnError(rc, rounds);

  return ArrayBuffer::copy(output);
}

std::shared_ptr<ArrayBuffer> HybridCypher::chacha8(const std::shared_ptr<ArrayBuffer>& key,
                                                   const std::shared_ptr<ArrayBuffer>& nonce,
                                                   const std::shared_ptr<ArrayBuffer>& data) {
  return chacha(key, nonce, data, 8);
}

std::shared_ptr<ArrayBuffer> HybridCypher::chacha12(const std::shared_ptr<ArrayBuffer>& key,
                                                    const std::shared_ptr<ArrayBuffer>& nonce,
                                                    const std::shared_ptr<ArrayBuffer>& data) {
  return chacha(key, nonce, data, 12);
}

std::shared_ptr<ArrayBuffer> HybridCypher::chacha20(const std::shared_ptr<ArrayBuffer>& key,
                                                    const std::shared_ptr<ArrayBuffer>& nonce,
                                                    const std::shared_ptr<ArrayBuffer>& data) {
  return chacha(key, nonce, data, 20);
}
