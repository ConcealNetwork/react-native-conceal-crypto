/*
 * Standalone runner for the native ChaCha used by HybridConcealCrypto (no Nitro / RN).
 * Usage: chacha_parity <8|12> <key_hex> <iv_hex> <data_hex>
 * Prints the ciphertext as lowercase hex on stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha.h"

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static uint8_t *from_hex(const char *hex, size_t *len) {
  size_t n = strlen(hex);
  if (n % 2) return NULL;
  uint8_t *out = malloc(n / 2 ? n / 2 : 1);
  if (!out) return NULL;
  for (size_t i = 0; i < n / 2; i++) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      free(out);
      return NULL;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  *len = n / 2;
  return out;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: %s <8|12> <key_hex> <iv_hex> <data_hex>\n", argv[0]);
    return 2;
  }
  int rounds = atoi(argv[1]);
  if (rounds != 8 && rounds != 12) {
    fprintf(stderr, "rounds must be 8 or 12\n");
    return 2;
  }
  size_t key_len = 0, iv_len = 0, data_len = 0;
  uint8_t *key = from_hex(argv[2], &key_len);
  uint8_t *iv = from_hex(argv[3], &iv_len);
  uint8_t *data = from_hex(argv[4], &data_len);
  if (!key || !iv || !data) {
    fprintf(stderr, "invalid hex input\n");
    return 2;
  }
  /* Same size checks as HybridConcealCrypto::chacha8 / chacha12 */
  if (key_len != CHACHA_KEY_SIZE) {
    fprintf(stderr, "Key must be exactly 32 bytes\n");
    return 3;
  }
  if (iv_len != CHACHA_IV_SIZE) {
    fprintf(stderr, "IV must be exactly 8 bytes\n");
    return 3;
  }

  uint8_t *out = malloc(data_len ? data_len : 1);
  if (!out) return 2;
  if (rounds == 8) {
    chacha8_xor(data, data_len, key, iv, out);
  } else {
    chacha12_xor(data, data_len, key, iv, out);
  }

  for (size_t i = 0; i < data_len; i++) printf("%02x", out[i]);
  printf("\n");

  free(key);
  free(iv);
  free(data);
  free(out);
  return 0;
}
