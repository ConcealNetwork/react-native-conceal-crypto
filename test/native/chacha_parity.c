/*
 * Standalone runner for the native ChaCha used by HybridConcealCrypto (no Nitro / RN).
 * Usage: chacha_parity <8|12> <key_hex> <iv_hex> <data_hex>
 *        chacha_parity ietf <8|12|20> <key_hex> <nonce_hex> <data_hex>
 *        chacha_parity ietf-len <rounds> <length>
 * Prints the ciphertext as lowercase hex on stdout. IETF modes exit with -CHACHA_ERR_* on error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha.h"

/* IETF modes only; must not collide with -CHACHA_ERR_* exit codes. */
#define EXIT_USAGE 64

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

static int run_ietf(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s ietf <8|12|20> <key_hex> <nonce_hex> <data_hex>\n", argv[0]);
    return EXIT_USAGE;
  }
  int status;
  size_t key_len = 0, nonce_len = 0, data_len = 0;
  uint8_t *key = from_hex(argv[3], &key_len);
  uint8_t *nonce = from_hex(argv[4], &nonce_len);
  uint8_t *data = from_hex(argv[5], &data_len);
  uint8_t *out = malloc(data_len ? data_len : 1);
  if (!key || !nonce || !data || !out) {
    fprintf(stderr, "invalid hex input\n");
    status = EXIT_USAGE;
  } else {
    int rc = chacha_ietf_xor(data, data_len, key, key_len, nonce, nonce_len, atoi(argv[2]), out);
    if (rc == CHACHA_OK) {
      for (size_t i = 0; i < data_len; i++) printf("%02x", out[i]);
      printf("\n");
    }
    status = -rc;
  }
  free(key);
  free(nonce);
  free(data);
  free(out);
  return status;
}

/* Length validation only: an accepted length is never encrypted (it may be 256 GiB). */
static int run_ietf_len(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s ietf-len <rounds> <length>\n", argv[0]);
    return EXIT_USAGE;
  }
  static const uint8_t key[CHACHA_KEY_SIZE];
  static const uint8_t nonce[CHACHA_NONCE_SIZE];
  int rounds = atoi(argv[2]);
  size_t length = (size_t)strtoull(argv[3], NULL, 10);
  int rc = chacha_ietf_check(length, sizeof key, sizeof nonce, rounds);
  if (rc != CHACHA_OK)
    rc = chacha_ietf_xor(NULL, length, key, sizeof key, nonce, sizeof nonce, rounds, NULL);
  return -rc;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "ietf") == 0) return run_ietf(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "ietf-len") == 0) return run_ietf_len(argc, argv);
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
