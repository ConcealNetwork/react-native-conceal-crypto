/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.

Modified and modularized for ChaCha12 integration – Acktarius 2025
*/

#include <string.h>

#include "chacha.h"

/* Convenience wrapper for ChaCha12 */
void chacha12_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
                    uint64_t counter) {
  chacha_block(out, key, nonce, counter, 12);
}

/* Stream cipher function with modern signature */
void chacha12_xor(const uint8_t *data, size_t length, const uint8_t *key, const uint8_t *iv,
                  uint8_t *cipher) {
  uint8_t keystream[64];
  uint8_t tmp[64];
  uint64_t counter = 0;
  size_t remaining = length;

  if (!length) return;

  do {
    size_t block_size = (remaining < 64) ? remaining : 64;

    /* Generate keystream block */
    chacha_block(keystream, key, iv, counter, 12);

    /* XOR with data */
    if (block_size == 64) {
      /* Full block - XOR directly */
      for (size_t i = 0; i < 64; i++) {
        cipher[i] = data[i] ^ keystream[i];
      }
    } else {
      /* Partial block - copy to temp buffer first */
      memcpy(tmp, data, block_size);
      for (size_t i = 0; i < block_size; i++) {
        cipher[i] = tmp[i] ^ keystream[i];
      }
    }

    counter++;
    remaining -= block_size;
    data += block_size;
    cipher += block_size;
  } while (remaining > 0);
}

/* Legacy function for backward compatibility */
void chacha12(const void *data, size_t length, const uint8_t *key, const uint8_t *iv,
              char *cipher) {
  chacha12_xor((const uint8_t *)data, length, key, iv, (uint8_t *)cipher);
}
