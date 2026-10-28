/*
 * Standalone runner for the native Argon2id KDF (no Nitro / RN).
 * Usage: argon2id_runner derive <pw_hex> <salt_hex> <m> <t> <p>
 *        argon2id_runner check <pw_len> <salt_len> <m> <t> <p>
 *        argon2id_runner open <pw_hex> <salt_hex> <m> <t> <p> <nonce_hex> <cipher_hex>
 * derive prints the 32-byte key as lowercase hex; open prints the secretbox plaintext as hex
 * and exits 1 on authentication failure. All modes exit with -ARGON2ID_ERR_* on KDF error.
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2id_kdf.h"

/* Must not collide with -ARGON2ID_ERR_* exit codes. */
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

static int parse_u32(const char *s, uint32_t *out) {
  char *end;
  unsigned long v = strtoul(s, &end, 10);
  if (*s == '\0' || *end != '\0' || v > UINT32_MAX) return -1;
  *out = (uint32_t)v;
  return 0;
}

static int parse_costs(char **argv, uint32_t *m, uint32_t *t, uint32_t *p) {
  return parse_u32(argv[0], m) || parse_u32(argv[1], t) || parse_u32(argv[2], p) ? -1 : 0;
}

static int run_derive(int argc, char **argv) {
  if (argc != 7) {
    fprintf(stderr, "usage: %s derive <pw_hex> <salt_hex> <m> <t> <p>\n", argv[0]);
    return EXIT_USAGE;
  }
  uint32_t m, t, p;
  if (parse_costs(argv + 4, &m, &t, &p)) return EXIT_USAGE;
  int status;
  size_t pw_len = 0, salt_len = 0;
  uint8_t *pw = from_hex(argv[2], &pw_len);
  uint8_t *salt = from_hex(argv[3], &salt_len);
  if (!pw || !salt) {
    fprintf(stderr, "invalid hex input\n");
    status = EXIT_USAGE;
  } else {
    uint8_t key[ARGON2ID_KEY_SIZE];
    int rc = argon2id_derive(pw, pw_len, salt, salt_len, m, t, p, key);
    if (rc == ARGON2ID_OK) {
      for (size_t i = 0; i < sizeof key; i++) printf("%02x", key[i]);
      printf("\n");
    }
    status = -rc;
  }
  free(pw);
  free(salt);
  return status;
}

static int run_check(int argc, char **argv) {
  if (argc != 7) {
    fprintf(stderr, "usage: %s check <pw_len> <salt_len> <m> <t> <p>\n", argv[0]);
    return EXIT_USAGE;
  }
  uint32_t pw_len, salt_len, m, t, p;
  if (parse_u32(argv[2], &pw_len) || parse_u32(argv[3], &salt_len) ||
      parse_costs(argv + 4, &m, &t, &p))
    return EXIT_USAGE;
  return -argon2id_check(pw_len, salt_len, m, t, p);
}

static int run_open(int argc, char **argv) {
  if (argc != 9) {
    fprintf(stderr, "usage: %s open <pw_hex> <salt_hex> <m> <t> <p> <nonce_hex> <cipher_hex>\n",
            argv[0]);
    return EXIT_USAGE;
  }
  uint32_t m, t, p;
  if (parse_costs(argv + 4, &m, &t, &p)) return EXIT_USAGE;
  int status;
  size_t pw_len = 0, salt_len = 0, nonce_len = 0, cipher_len = 0;
  uint8_t key[ARGON2ID_KEY_SIZE];
  uint8_t *pw = from_hex(argv[2], &pw_len);
  uint8_t *salt = from_hex(argv[3], &salt_len);
  uint8_t *nonce = from_hex(argv[7], &nonce_len);
  uint8_t *cipher = from_hex(argv[8], &cipher_len);
  uint8_t *plain = malloc(cipher_len > crypto_secretbox_MACBYTES ? cipher_len : 1);
  if (!pw || !salt || !nonce || !cipher || !plain || nonce_len != crypto_secretbox_NONCEBYTES ||
      cipher_len < crypto_secretbox_MACBYTES) {
    fprintf(stderr, "invalid input\n");
    status = EXIT_USAGE;
  } else {
    int rc = argon2id_derive(pw, pw_len, salt, salt_len, m, t, p, key);
    if (rc != ARGON2ID_OK) {
      status = -rc;
    } else if (crypto_secretbox_open_easy(plain, cipher, cipher_len, nonce, key) != 0) {
      status = 1;
    } else {
      for (size_t i = 0; i < cipher_len - crypto_secretbox_MACBYTES; i++) printf("%02x", plain[i]);
      printf("\n");
      status = 0;
    }
  }
  sodium_memzero(key, sizeof key);
  free(pw);
  free(salt);
  free(nonce);
  free(cipher);
  free(plain);
  return status;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "derive") == 0) return run_derive(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "check") == 0) return run_check(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "open") == 0) return run_open(argc, argv);
  fprintf(stderr, "usage: %s <derive|check|open> ...\n", argv[0]);
  return EXIT_USAGE;
}
