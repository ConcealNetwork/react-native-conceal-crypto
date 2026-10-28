/*
 * Copyright (c) 2025 - 2026 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "argon2id_kdf.h"

#include <sodium.h>

int argon2id_check(size_t pw_len, size_t salt_len, uint32_t m, uint32_t t, uint32_t p) {
  if (pw_len > ARGON2ID_MAX_PASSWORD) return ARGON2ID_ERR_PASSWORD;
  if (salt_len != ARGON2ID_SALT_SIZE) return ARGON2ID_ERR_SALT;
  if (p != 1) return ARGON2ID_ERR_PARALLELISM;
  if (t < 1 || t > 64) return ARGON2ID_ERR_ITERATIONS;
  if (m < 8 || m > 65536) return ARGON2ID_ERR_MEMORY;
  return ARGON2ID_OK;
}

int argon2id_derive(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                    uint32_t m, uint32_t t, uint32_t p, uint8_t *out) {
  static const char empty = 0;
  int rc = argon2id_check(pw_len, salt_len, m, t, p);

  if (rc != ARGON2ID_OK) return rc;
  if (sodium_init() < 0) return ARGON2ID_ERR_INTERNAL;
  /* libsodium's Argon2id always runs a single lane, which is why p must be 1. */
  if (crypto_pwhash(out, ARGON2ID_KEY_SIZE, pw_len ? (const char *)pw : &empty, pw_len, salt,
                    (unsigned long long)t, (size_t)m * 1024, crypto_pwhash_ALG_ARGON2ID13) != 0)
    return ARGON2ID_ERR_INTERNAL;
  return ARGON2ID_OK;
}
