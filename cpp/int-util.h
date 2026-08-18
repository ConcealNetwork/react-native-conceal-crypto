// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2025 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php LICENCE

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#include <stdlib.h>

#define inline __inline

static inline uint32_t rol32(uint32_t x, int r) {
  static_assert(sizeof(uint32_t) == sizeof(unsigned int), "this code assumes 32-bit integers");
  return _rotl(x, r);
}

static inline uint64_t rol64(uint64_t x, int r) { return _rotl64(x, r); }

#else

static inline uint32_t rol32(uint32_t x, int r) { return (x << (r & 31)) | (x >> (-r & 31)); }

static inline uint64_t rol64(uint64_t x, int r) { return (x << (r & 63)) | (x >> (-r & 63)); }

#endif

#define IDENT32(x) ((uint32_t)(x))
#define IDENT64(x) ((uint64_t)(x))

#define SWAP32(x)                                                           \
  ((((uint32_t)(x)&0x000000ff) << 24) | (((uint32_t)(x)&0x0000ff00) << 8) | \
   (((uint32_t)(x)&0x00ff0000) >> 8) | (((uint32_t)(x)&0xff000000) >> 24))

static inline uint32_t ident32(uint32_t x) { return x; }
static inline uint32_t swap32(uint32_t x) {
  x = ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
  return (x << 16) | (x >> 16);
}

// Assume little endian for simplicity
#define SWAP32LE IDENT32
#define SWAP32BE SWAP32
