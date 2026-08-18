/*
 * chacha.h
 * Unified header for ChaCha implementations (8, 12, 20 rounds)
 * Based on D. J. Bernstein's chacha-merged.c (20080118) – Public Domain.
 */

#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA_KEY_SIZE 32   /* 256‑bit key */
#define CHACHA_BLOCK_SIZE 64 /* 64‑byte block */
#define CHACHA_IV_SIZE 8     /* legacy nonce */
#define CHACHA_NONCE_SIZE 12 /* modern nonce length */

/* Core block function (rounds parameter decides 8/12/20 etc.) */
void chacha_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter,
                  int rounds);

/* Convenience wrappers for specific variants */
void chacha8_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
                   uint64_t counter);

void chacha12_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
                    uint64_t counter);

void chacha20_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
                    uint64_t counter);

/* Stream cipher functions with modern signatures */
void chacha8_xor(const uint8_t *data, size_t length, const uint8_t *key, const uint8_t *iv,
                 uint8_t *cipher);
void chacha12_xor(const uint8_t *data, size_t length, const uint8_t *key, const uint8_t *iv,
                  uint8_t *cipher);

/* Legacy functions for backward compatibility */
void chacha8(const void *data, size_t length, const uint8_t *key, const uint8_t *iv, char *cipher);
void chacha12(const void *data, size_t length, const uint8_t *key, const uint8_t *iv, char *cipher);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA_H */
