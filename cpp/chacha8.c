/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include <memory.h>
#include <stdio.h>

#include "chacha.h"
#include "int-util.h"

/*
 * The following macros are used to obtain exact-width results.
 */
#define U8V(v) ((uint8_t)(v)&UINT8_C(0xFF))
#define U32V(v) ((uint32_t)(v)&UINT32_C(0xFFFFFFFF))

/*
 * The following macros load words from an array of bytes with
 * different types of endianness, and vice versa.
 */
#define U8TO32_LITTLE(p) SWAP32LE(((const uint32_t *)(p))[0])
#define U32TO8_LITTLE(p, v) (((uint32_t *)(p))[0] = SWAP32LE(v))

#define ROTATE(v, c) (rol32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d) \
  a = PLUS(a, b);                \
  d = ROTATE(XOR(d, a), 16);     \
  c = PLUS(c, d);                \
  b = ROTATE(XOR(b, c), 12);     \
  a = PLUS(a, b);                \
  d = ROTATE(XOR(d, a), 8);      \
  c = PLUS(c, d);                \
  b = ROTATE(XOR(b, c), 7);

static const char sigma[] = "expand 32-byte k";

/* Core block function with configurable rounds */
void chacha_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter,
                  int rounds) {
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  int i;

  j0 = U8TO32_LITTLE(sigma + 0);
  j1 = U8TO32_LITTLE(sigma + 4);
  j2 = U8TO32_LITTLE(sigma + 8);
  j3 = U8TO32_LITTLE(sigma + 12);
  j4 = U8TO32_LITTLE(key + 0);
  j5 = U8TO32_LITTLE(key + 4);
  j6 = U8TO32_LITTLE(key + 8);
  j7 = U8TO32_LITTLE(key + 12);
  j8 = U8TO32_LITTLE(key + 16);
  j9 = U8TO32_LITTLE(key + 20);
  j10 = U8TO32_LITTLE(key + 24);
  j11 = U8TO32_LITTLE(key + 28);
  j12 = (uint32_t)(counter & 0xFFFFFFFF);
  j13 = (uint32_t)(counter >> 32);
  j14 = U8TO32_LITTLE(nonce + 0);
  j15 = U8TO32_LITTLE(nonce + 4);

  x0 = j0;
  x1 = j1;
  x2 = j2;
  x3 = j3;
  x4 = j4;
  x5 = j5;
  x6 = j6;
  x7 = j7;
  x8 = j8;
  x9 = j9;
  x10 = j10;
  x11 = j11;
  x12 = j12;
  x13 = j13;
  x14 = j14;
  x15 = j15;

  for (i = rounds; i > 0; i -= 2) {
    QUARTERROUND(x0, x4, x8, x12)
    QUARTERROUND(x1, x5, x9, x13)
    QUARTERROUND(x2, x6, x10, x14)
    QUARTERROUND(x3, x7, x11, x15)
    QUARTERROUND(x0, x5, x10, x15)
    QUARTERROUND(x1, x6, x11, x12)
    QUARTERROUND(x2, x7, x8, x13)
    QUARTERROUND(x3, x4, x9, x14)
  }

  x0 = PLUS(x0, j0);
  x1 = PLUS(x1, j1);
  x2 = PLUS(x2, j2);
  x3 = PLUS(x3, j3);
  x4 = PLUS(x4, j4);
  x5 = PLUS(x5, j5);
  x6 = PLUS(x6, j6);
  x7 = PLUS(x7, j7);
  x8 = PLUS(x8, j8);
  x9 = PLUS(x9, j9);
  x10 = PLUS(x10, j10);
  x11 = PLUS(x11, j11);
  x12 = PLUS(x12, j12);
  x13 = PLUS(x13, j13);
  x14 = PLUS(x14, j14);
  x15 = PLUS(x15, j15);

  U32TO8_LITTLE(out + 0, x0);
  U32TO8_LITTLE(out + 4, x1);
  U32TO8_LITTLE(out + 8, x2);
  U32TO8_LITTLE(out + 12, x3);
  U32TO8_LITTLE(out + 16, x4);
  U32TO8_LITTLE(out + 20, x5);
  U32TO8_LITTLE(out + 24, x6);
  U32TO8_LITTLE(out + 28, x7);
  U32TO8_LITTLE(out + 32, x8);
  U32TO8_LITTLE(out + 36, x9);
  U32TO8_LITTLE(out + 40, x10);
  U32TO8_LITTLE(out + 44, x11);
  U32TO8_LITTLE(out + 48, x12);
  U32TO8_LITTLE(out + 52, x13);
  U32TO8_LITTLE(out + 56, x14);
  U32TO8_LITTLE(out + 60, x15);
}

/* Convenience wrapper for ChaCha8 */
void chacha8_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[8],
                   uint64_t counter) {
  chacha_block(out, key, nonce, counter, 8);
}

/* Stream cipher function with modern signature */
void chacha8_xor(const uint8_t *data, size_t length, const uint8_t *key, const uint8_t *iv,
                 uint8_t *cipher) {
  uint8_t keystream[64];
  uint8_t tmp[64];
  uint64_t counter = 0;
  size_t remaining = length;

  if (!length) return;

  do {
    size_t block_size = (remaining < 64) ? remaining : 64;

    /* Generate keystream block */
    chacha_block(keystream, key, iv, counter, 8);

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
void chacha8(const void *data, size_t length, const uint8_t *key, const uint8_t *iv, char *cipher) {
  chacha8_xor((const uint8_t *)data, length, key, iv, (uint8_t *)cipher);
}