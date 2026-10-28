#!/bin/bash

# Add copyright header to C++ files
add_copyright() {
    local file="$1"
    local temp_file=$(mktemp)
    year=$(date +%Y)
    
    cat > "$temp_file" << 'EOF'
/*
 * Copyright (c) 2025 - $year Acktarius, Conceal Devs
 * 
 * This file is part of react-native-conceal-crypto.
 * 
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

EOF
    
    cat "$file" >> "$temp_file"
    mv "$temp_file" "$file"
    echo "Added copyright to $file"
}

# Add copyright to C++ files
add_copyright "cpp/argon2id_kdf.c"
add_copyright "cpp/argon2id_kdf.h"
add_copyright "cpp/HybridConcealCrypto.cpp"
add_copyright "cpp/HybridConcealCrypto.hpp"
add_copyright "cpp/HybridCypher.cpp"
add_copyright "cpp/HybridCypher.hpp"
add_copyright "cpp/chacha8.h"
add_copyright "cpp/chacha8.c"
add_copyright "cpp/int-util.h"
add_copyright "cpp/install.cpp"

echo "Copyright headers added to all C++ files"
