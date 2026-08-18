/*
 * Copyright (c) 2025 Acktarius, Conceal Devs
 *
 * This file is part of react-native-conceal-crypto.
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */
#include <NitroModules/HybridObjectRegistry.hpp>

#include "HybridConcealCrypto.hpp"

using namespace margelo::nitro::concealcrypto;

extern "C" {

void initializeNativeConcealCrypto() {
  margelo::nitro::HybridObjectRegistry::registerHybridObjectConstructor(
      "ConcealCrypto", []() -> std::shared_ptr<margelo::nitro::HybridObject> {
        return std::make_shared<HybridConcealCrypto>();
      });
}

}  // extern "C"
