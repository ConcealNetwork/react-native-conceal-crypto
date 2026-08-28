#!/usr/bin/env bash
#
# Compiles and runs the standalone C++ mnemonic codec tests.
# The mnemonic codec (cpp/Mnemonics) is pure C++ with no React Native
# dependencies, so a plain host compiler is enough - no RN host app needed.
set -euo pipefail

cd "$(dirname "$0")/.."

CXX="${CXX:-c++}"
OUT_DIR="build/tests"

mkdir -p "$OUT_DIR"

# shellcheck disable=SC2086
"$CXX" -std=c++17 -Wall -Wextra -O1 \
  cpp/Mnemonics/Mnemonics.cpp \
  cpp/Mnemonics/CRC32.cpp \
  tests/mnemonics_test.cpp \
  -o "$OUT_DIR/mnemonics_test"

"$OUT_DIR/mnemonics_test"
