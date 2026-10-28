/*
 * Standalone runner for native English mnemonics (no Nitro / RN).
 * Usage: mnemonic_runner encode <64-hex>
 *        mnemonic_runner decode <phrase...>
 * encode prints the 25-word phrase; decode prints lowercase 64-hex.
 * Exit 0 on success, 1 on invalid input, 64 on usage error.
 */

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "Cryptonote/CryptoTypes.h"
#include "Mnemonics/Mnemonics.h"
#include "Mnemonics/WordList.h"

namespace {

constexpr int EXIT_OK = 0;
constexpr int EXIT_INVALID = 1;
constexpr int EXIT_USAGE = 64;
constexpr size_t KEY_HEX_LEN = 64;
constexpr size_t KEY_SIZE = 32;

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse_key_hex(const std::string &hex, crypto::SecretKey &out) {
  if (hex.size() != KEY_HEX_LEN) return false;
  for (size_t i = 0; i < KEY_SIZE; i++) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.data[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

std::string key_to_hex(const crypto::SecretKey &key) {
  static const char *digits = "0123456789abcdef";
  std::string out(KEY_HEX_LEN, '0');
  for (size_t i = 0; i < KEY_SIZE; i++) {
    out[2 * i] = digits[key.data[i] >> 4];
    out[2 * i + 1] = digits[key.data[i] & 0xf];
  }
  return out;
}

std::vector<std::string> split_words(const std::string &phrase) {
  std::istringstream stream(phrase);
  std::vector<std::string> words;
  for (std::string word; stream >> word;) {
    for (char &c : word) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    words.push_back(word);
  }
  return words;
}

bool phrase_structurally_valid(const std::vector<std::string> &words) {
  if (words.size() != 25) return false;
  for (const auto &word : words) {
    if (std::find(mnemonics::WordList::English.begin(), mnemonics::WordList::English.end(), word) ==
        mnemonics::WordList::English.end()) {
      return false;
    }
  }
  return mnemonics::hasValidChecksum(words);
}

int run_encode(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s encode <64-hex>\n", argv[0]);
    return EXIT_USAGE;
  }
  crypto::SecretKey key{};
  if (!parse_key_hex(argv[2], key)) return EXIT_INVALID;
  const std::string phrase = mnemonics::privateKeyToMnemonic(key);
  if (phrase.empty()) return EXIT_INVALID;
  std::printf("%s\n", phrase.c_str());
  return EXIT_OK;
}

int run_decode(int argc, char **argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s decode <phrase...>\n", argv[0]);
    return EXIT_USAGE;
  }
  std::string phrase = argv[2];
  for (int i = 3; i < argc; i++) {
    phrase.push_back(' ');
    phrase.append(argv[i]);
  }
  const auto words = split_words(phrase);
  if (!phrase_structurally_valid(words)) return EXIT_INVALID;
  const crypto::SecretKey key = mnemonics::mnemonicToPrivateKey(words);
  std::printf("%s\n", key_to_hex(key).c_str());
  return EXIT_OK;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s encode|decode ...\n", argv[0]);
    return EXIT_USAGE;
  }
  if (std::strcmp(argv[1], "encode") == 0) return run_encode(argc, argv);
  if (std::strcmp(argv[1], "decode") == 0) return run_decode(argc, argv);
  std::fprintf(stderr, "usage: %s encode|decode ...\n", argv[0]);
  return EXIT_USAGE;
}
