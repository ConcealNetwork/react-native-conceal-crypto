/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "mn_random.h"

#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

// Try to include libsodium if available
#ifdef HAVE_SODIUM_H
#include <sodium.h>
#define SODIUM_AVAILABLE 1

// Global sodium initializer to avoid per-thread initialization race conditions
struct SodiumInitializer {
  SodiumInitializer() {
    if (sodium_init() == -1) {
      throw std::runtime_error("mn_random: sodium_init failed - libsodium initialization error");
    }
  }
};
static const SodiumInitializer sodium_initializer;

#else
#define SODIUM_AVAILABLE 0
#endif

// Thread-local random device for fallback (initialized once per thread)
thread_local std::random_device* g_random_device = nullptr;

/**
 * Initialize thread-local random device if needed
 * This ensures per-thread RNG isolation and avoids race conditions
 */
static std::random_device& get_random_device() {
  if (!g_random_device) {
    g_random_device = new std::random_device();

    // Verify the random device has entropy
    if (g_random_device->entropy() == 0) {
      throw std::runtime_error("mn_random: Hardware random number generator not available");
    }
  }
  return *g_random_device;
}

/**
 * Production-ready secure random number generator
 * Uses libsodium if available, otherwise falls back to hardware RNG
 */
std::string mn_random(int bits) {
  if (bits % 32 != 0) {
    throw std::invalid_argument("mn_random failed: Invalid number of bits - " +
                                std::to_string(bits) + " (must be multiple of 32)");
  }

  const int byteLength = bits / 8;
  std::vector<uint8_t> buffer(byteLength);

#if SODIUM_AVAILABLE
  // Use libsodium for maximum security (preferred)
  // sodium_initializer ensures sodium_init() was called once at startup
  randombytes_buf(buffer.data(), buffer.size());
#else
  // Fallback to hardware random device
  std::random_device& rd = get_random_device();

  for (int i = 0; i < byteLength; ++i) {
    buffer[i] = static_cast<uint8_t>(rd());
  }
#endif

  // Convert to hex string
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  for (auto b : buffer) {
    oss << std::setw(2) << static_cast<int>(b);
  }

  return oss.str();
}

/**
 * Generate random bytes as vector
 */
std::vector<uint8_t> mn_random_bytes(int bytes) {
  if (bytes <= 0) {
    throw std::invalid_argument("mn_random_bytes failed: Number of bytes must be positive");
  }

  std::vector<uint8_t> buffer(bytes);

#if SODIUM_AVAILABLE
  // Use libsodium for maximum security (preferred)
  // sodium_initializer ensures sodium_init() was called once at startup
  randombytes_buf(buffer.data(), buffer.size());
#else
  // Fallback to hardware random device
  std::random_device& rd = get_random_device();

  for (int i = 0; i < bytes; ++i) {
    buffer[i] = static_cast<uint8_t>(rd());
  }
#endif

  return buffer;
}
