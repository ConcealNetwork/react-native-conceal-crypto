/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 * 
 * This file is part of react-native-conceal-crypto.
 * 
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#pragma once
#include "../nitrogen/generated/shared/c++/HybridMnemonicsSpec.hpp"
#include <string>
#include <memory>

namespace margelo::nitro::concealcrypto {

class HybridMnemonics : public HybridMnemonicsSpec {
 public:
  HybridMnemonics();

  // Mnemonic encoding/decoding functions
  std::string mn_encode(const std::string& privateKeyHex) override;
  std::string mn_decode(const std::string& mnemonicPhrase) override;
};

}  // namespace margelo::nitro::concealcrypto

