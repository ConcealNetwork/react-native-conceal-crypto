/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#pragma once
#include <memory>

#include "../nitrogen/generated/shared/c++/HybridCypherSpec.hpp"

namespace margelo::nitro::concealcrypto {

class HybridCypher : public HybridCypherSpec {
 public:
  HybridCypher();

  // IETF ChaCha (32-byte key, 12-byte nonce) with 8/12/20 rounds
  std::shared_ptr<ArrayBuffer> chacha8(const std::shared_ptr<ArrayBuffer>& key,
                                       const std::shared_ptr<ArrayBuffer>& nonce,
                                       const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> chacha12(const std::shared_ptr<ArrayBuffer>& key,
                                        const std::shared_ptr<ArrayBuffer>& nonce,
                                        const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> chacha20(const std::shared_ptr<ArrayBuffer>& key,
                                        const std::shared_ptr<ArrayBuffer>& nonce,
                                        const std::shared_ptr<ArrayBuffer>& data) override;

 private:
  static std::shared_ptr<ArrayBuffer> chacha(const std::shared_ptr<ArrayBuffer>& key,
                                             const std::shared_ptr<ArrayBuffer>& nonce,
                                             const std::shared_ptr<ArrayBuffer>& data, int rounds);
};

}  // namespace margelo::nitro::concealcrypto
