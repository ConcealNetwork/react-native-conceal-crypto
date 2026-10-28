/*
 * Copyright (c) 2025 - 2026 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef ARGON2ID_KDF_H
#define ARGON2ID_KDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARGON2ID_KEY_SIZE 32
#define ARGON2ID_SALT_SIZE 16
#define ARGON2ID_MAX_PASSWORD 1024

#define ARGON2ID_OK 0
#define ARGON2ID_ERR_PASSWORD (-1)
#define ARGON2ID_ERR_SALT (-2)
#define ARGON2ID_ERR_PARALLELISM (-3)
#define ARGON2ID_ERR_ITERATIONS (-4)
#define ARGON2ID_ERR_MEMORY (-5)
#define ARGON2ID_ERR_INTERNAL (-6)

/* Validation used by argon2id_derive: password <= 1024 bytes, salt 16, p 1, t 1..64,
 * m 8..65536 KiB. Nothing is clamped. Returns ARGON2ID_OK or ARGON2ID_ERR_*. */
int argon2id_check(size_t pw_len, size_t salt_len, uint32_t m, uint32_t t, uint32_t p);

/* Argon2id v0x13 (libsodium crypto_pwhash), m in KiB; writes ARGON2ID_KEY_SIZE bytes to out.
 * pw may be NULL only when pw_len is 0. Returns ARGON2ID_OK or ARGON2ID_ERR_*. */
int argon2id_derive(const uint8_t *pw, size_t pw_len, const uint8_t *salt, size_t salt_len,
                    uint32_t m, uint32_t t, uint32_t p, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ARGON2ID_KDF_H */
