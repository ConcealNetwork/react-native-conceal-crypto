/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.

IETF (12-byte nonce, 32-bit counter) variant built on chacha_block
*/

#include "chacha.h"

int chacha_ietf_check(size_t length, size_t key_len, size_t nonce_len, int rounds) {
  if (key_len != CHACHA_KEY_SIZE) return CHACHA_ERR_KEY;
  if (nonce_len != CHACHA_NONCE_SIZE) return CHACHA_ERR_NONCE;
  if (rounds != 8 && rounds != 12 && rounds != 20) return CHACHA_ERR_ROUNDS;
  if ((uint64_t)length > ((uint64_t)UINT32_MAX + 1) * CHACHA_BLOCK_SIZE) return CHACHA_ERR_LENGTH;
  return CHACHA_OK;
}

int chacha_ietf_xor(const uint8_t *data, size_t length, const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len, int rounds, uint8_t *out) {
  uint8_t keystream[CHACHA_BLOCK_SIZE];
  uint64_t high;
  int rc = chacha_ietf_check(length, key_len, nonce_len, rounds);

  if (rc != CHACHA_OK) return rc;

  /* chacha_block puts counter low/high in words 12/13 and nonce[0..7] in 14/15:
   * IETF word 13 is nonce[0..3], so it rides in the counter's high half. */
  high = (uint64_t)nonce[0] | (uint64_t)nonce[1] << 8 | (uint64_t)nonce[2] << 16 |
         (uint64_t)nonce[3] << 24;

  for (uint64_t b = 0; length > 0; b++) {
    size_t block_size = length < CHACHA_BLOCK_SIZE ? length : CHACHA_BLOCK_SIZE;

    chacha_block(keystream, key, nonce + 4, high << 32 | b, rounds);
    for (size_t i = 0; i < block_size; i++) out[i] = data[i] ^ keystream[i];

    length -= block_size;
    data += block_size;
    out += block_size;
  }
  return CHACHA_OK;
}
