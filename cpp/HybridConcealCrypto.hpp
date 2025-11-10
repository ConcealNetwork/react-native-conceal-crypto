/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 * 
 * This file is part of react-native-conceal-crypto.
 * 
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#pragma once
#include "../nitrogen/generated/shared/c++/HybridConcealCryptoSpec.hpp"
#include "Hmac.hpp"
#include "HybridCryptonote.hpp"
#include "HybridMnemonics.hpp"
#include <vector>
#include <string>
#include <memory>

namespace margelo::nitro::concealcrypto {

class HybridConcealCrypto : public HybridConcealCryptoSpec {
 public:
  HybridConcealCrypto();

  // Basic crypto functions
  std::shared_ptr<ArrayBuffer> hextobin(const std::string& hex) override;
  std::string bintohex(const std::shared_ptr<ArrayBuffer>& buffer) override;
  std::string bin2base64(const std::shared_ptr<ArrayBuffer>& buffer) override;
  std::shared_ptr<ArrayBuffer> base642bin(const std::string& base64) override;
  std::shared_ptr<ArrayBuffer> chacha8(const std::shared_ptr<ArrayBuffer>& input,
                                       const std::shared_ptr<ArrayBuffer>& key,
                                       const std::shared_ptr<ArrayBuffer>& iv) override;
  std::shared_ptr<ArrayBuffer> chacha12(const std::shared_ptr<ArrayBuffer>& input,
                                        const std::shared_ptr<ArrayBuffer>& key,
                                        const std::shared_ptr<ArrayBuffer>& iv) override;
  std::shared_ptr<ArrayBuffer> hmacSha1(const std::shared_ptr<ArrayBuffer>& key,
                                        const std::shared_ptr<ArrayBuffer>& data) override;
  std::string random(double bits) override;
  std::shared_ptr<ArrayBuffer> randomBytes(double bytes) override;
  std::shared_ptr<ArrayBuffer> secretbox(const std::shared_ptr<ArrayBuffer>& message,
                                         const std::shared_ptr<ArrayBuffer>& nonce,
                                         const std::shared_ptr<ArrayBuffer>& key) override;
  std::optional<std::shared_ptr<ArrayBuffer>> secretboxOpen(const std::shared_ptr<ArrayBuffer>& ciphertext,
                                                             const std::shared_ptr<ArrayBuffer>& nonce,
                                                             const std::shared_ptr<ArrayBuffer>& key) override;

  // Cryptonote property getter
  std::shared_ptr<HybridCryptonoteSpec> getCryptonote() override;

  // Mnemonics property getter
  std::shared_ptr<HybridMnemonicsSpec> getMnemonics() override;

 private:
  std::shared_ptr<HybridCryptonoteSpec> _cryptonote;
  std::shared_ptr<HybridMnemonicsSpec> _mnemonics;
};

}  // namespace margelo::nitro::concealcrypto
