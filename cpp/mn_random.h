/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef MN_RANDOM_H
#define MN_RANDOM_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * Generate cryptographically secure random data in multiples of 32 bits
 * Returns hex string representation
 * @param bits Number of bits (must be multiple of 32)
 * @return Hex string of random data
 * @throws std::invalid_argument if bits is not multiple of 32
 * @throws std::runtime_error if random generation fails
 */
std::string mn_random(int bits);

/**
 * Generate cryptographically secure random bytes
 * @param bytes Number of bytes to generate
 * @return Vector of random bytes
 * @throws std::invalid_argument if bytes <= 0
 * @throws std::runtime_error if random generation fails
 */
std::vector<uint8_t> mn_random_bytes(int bytes);

#endif /* MN_RANDOM_H */
