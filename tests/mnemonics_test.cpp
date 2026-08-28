// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Please see the included LICENSE file for more information.
//
// Standalone regression tests for the pure C++ mnemonic codec
// (cpp/Mnemonics). No React Native host is required: the test binary is
// compiled directly against Mnemonics.cpp, CRC32.cpp and WordList.h.

#include "../cpp/Mnemonics/Mnemonics.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "../cpp/Cryptonote/CryptoTypes.h"
#include "../cpp/Mnemonics/WordList.h"

namespace {

int g_failures = 0;

void reportFailure(const char *what, const char *detail) {
  g_failures++;
  std::printf("  FAIL: %s (%s)\n", what, detail);
}

crypto::SecretKey makeKey(const uint8_t (&bytes)[32]) {
  crypto::SecretKey key;
  for (int i = 0; i < 32; i++) {
    key.data[i] = bytes[i];
  }
  return key;
}

bool isZeroKey(const crypto::SecretKey &key) {
  for (int i = 0; i < 32; i++) {
    if (key.data[i] != 0) {
      return false;
    }
  }
  return true;
}

bool keysEqual(const crypto::SecretKey &a, const crypto::SecretKey &b) {
  for (int i = 0; i < 32; i++) {
    if (a.data[i] != b.data[i]) {
      return false;
    }
  }
  return true;
}

crypto::SecretKey decode(const std::string &words) {
  return mnemonics::mnemonicToPrivateKey(words);
}

crypto::SecretKey decode(const std::vector<std::string> &words) {
  return mnemonics::mnemonicToPrivateKey(words);
}

std::vector<std::string> splitWords(const std::string &phrase) {
  std::vector<std::string> words;
  std::istringstream stream(phrase);
  for (std::string word; stream >> word;) {
    words.push_back(word);
  }
  return words;
}

std::string toUpper(const std::string &input) {
  std::string upper = input;
  std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
  return upper;
}

std::string capitalizeWords(const std::string &phrase) {
  std::string result;
  bool capitalizeNext = true;
  for (char c : phrase) {
    if (capitalizeNext && c != ' ') {
      result += static_cast<char>(::toupper(c));
      capitalizeNext = false;
    } else {
      result += c;
    }
    if (c == ' ') {
      capitalizeNext = true;
    }
  }
  return result;
}

/* Deterministic known-answer vector: this exact key/phrase pair must keep
   decoding and encoding to each other. */
const char *kKnownMnemonic =
    "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed update vague "
    "zinger boxes ornament renting glass gained island nabbing afield calamity boxes";

uint8_t kKnownKeyBytes[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                              0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

/* Regression for the mixed-case decode bug: phrases that differ only in
   casing must decode to the same private key as the lowercase phrase. */
void testMixedCaseDecodesSameKey() {
  const crypto::SecretKey expected = decode(kKnownMnemonic);

  if (isZeroKey(expected)) {
    reportFailure("mixed-case decode", "known vector unexpectedly failed to decode");
  }

  const crypto::SecretKey upper = decode(toUpper(kKnownMnemonic));
  if (!keysEqual(upper, expected)) {
    reportFailure("mixed-case decode", "fully upper-cased phrase decoded a different key");
  }

  const crypto::SecretKey capitalized = decode(capitalizeWords(kKnownMnemonic));
  if (!keysEqual(capitalized, expected)) {
    reportFailure("mixed-case decode", "capitalized phrase decoded a different key");
  }

  /* Mixed casing on a few individual words only. */
  std::vector<std::string> words = splitWords(kKnownMnemonic);
  words[0] = toUpper(words[0]);
  words[7] = toUpper(words[7]);
  words[24] = toUpper(words[24]);
  const crypto::SecretKey mixed = decode(words);
  if (!keysEqual(mixed, expected)) {
    reportFailure("mixed-case decode", "mixed-case phrase decoded a different key");
  }
}

void testKnownVectorRoundTrip() {
  const crypto::SecretKey expected = makeKey(kKnownKeyBytes);

  const crypto::SecretKey decoded = decode(kKnownMnemonic);
  if (!keysEqual(decoded, expected)) {
    reportFailure("known vector", "phrase did not decode to the known private key");
  }

  const std::string encoded = mnemonics::privateKeyToMnemonic(expected);
  if (encoded != kKnownMnemonic) {
    reportFailure("known vector", "private key did not encode to the known phrase");
  }
}

void testRoundTripMultipleKeys() {
  for (int seed = 1; seed <= 8; seed++) {
    uint8_t bytes[32];
    for (int i = 0; i < 32; i++) {
      bytes[i] = static_cast<uint8_t>((seed * 31 + i * 7) & 0xff);
    }
    /* Keep the key non-zero so a decode failure (zero key) stays detectable. */
    bytes[0] = static_cast<uint8_t>(seed);

    const crypto::SecretKey key = makeKey(bytes);
    const std::string phrase = mnemonics::privateKeyToMnemonic(key);

    if (phrase.empty()) {
      reportFailure("round trip", "encoding produced an empty phrase");
      continue;
    }

    if (splitWords(phrase).size() != 25) {
      reportFailure("round trip", "encoding did not produce 25 words");
    }

    const crypto::SecretKey decoded = decode(phrase);
    if (isZeroKey(decoded) || !keysEqual(decoded, key)) {
      reportFailure("round trip", "decoded key does not match the original key");
    }
  }
}

void testChecksumTamperingRejected() {
  std::vector<std::string> words = splitWords(kKnownMnemonic);

  /* Replace the checksum (last) word with a different valid word-list word. */
  std::vector<std::string> tampered = words;
  for (const auto *candidate : mnemonics::WordList::English) {
    if (candidate != tampered[24]) {
      tampered[24] = candidate;
      break;
    }
  }
  if (!isZeroKey(decode(tampered))) {
    reportFailure("checksum rejection", "tampered checksum word was accepted");
  }

  /* Replacing a data word also invalidates the checksum. */
  std::vector<std::string> tamperedData = words;
  for (const auto *candidate : mnemonics::WordList::English) {
    if (candidate != tamperedData[3]) {
      tamperedData[3] = candidate;
      break;
    }
  }
  if (!isZeroKey(decode(tamperedData))) {
    reportFailure("checksum rejection", "tampered data word was accepted");
  }

  if (mnemonics::hasValidChecksum(tampered)) {
    reportFailure("checksum rejection", "hasValidChecksum accepted a tampered phrase");
  }
  if (!mnemonics::hasValidChecksum(words)) {
    reportFailure("checksum rejection", "hasValidChecksum rejected a valid phrase");
  }
}

void testWrongWordCountRejected() {
  std::vector<std::string> words = splitWords(kKnownMnemonic);

  std::vector<std::string> tooFew(words.begin(), words.end() - 1);
  if (!isZeroKey(decode(tooFew))) {
    reportFailure("word count", "24-word phrase was accepted");
  }

  std::vector<std::string> tooMany = words;
  tooMany.push_back(words[0]);
  if (!isZeroKey(decode(tooMany))) {
    reportFailure("word count", "26-word phrase was accepted");
  }
}

void testUnknownWordsRejected() {
  std::vector<std::string> words = splitWords(kKnownMnemonic);

  std::vector<std::string> unknown = words;
  unknown[5] = "notaword";
  if (!isZeroKey(decode(unknown))) {
    reportFailure("unknown word", "phrase with an unknown word was accepted");
  }

  std::vector<std::string> unknownChecksum = words;
  unknownChecksum[24] = "zzzzz";
  if (!isZeroKey(decode(unknownChecksum))) {
    reportFailure("unknown word", "phrase with an unknown checksum word was accepted");
  }
}

void testChecksumWordDerivation() {
  const std::vector<std::string> words = splitWords(kKnownMnemonic);
  const std::vector<std::string> dataWords(words.begin(), words.end() - 1);
  if (mnemonics::getChecksumWord(dataWords) != words[24]) {
    reportFailure("checksum word", "derived checksum word does not match the known phrase");
  }
}

void testEmptyPhraseRejected() {
  if (!isZeroKey(decode(std::string("")))) {
    reportFailure("empty phrase", "empty input was accepted");
  }
}

}  // namespace

int main() {
  const struct {
    const char *name;
    void (*fn)();
  } tests[] = {
      {"known vector round trip", testKnownVectorRoundTrip},
      {"round trip multiple keys", testRoundTripMultipleKeys},
      {"mixed-case decodes same key", testMixedCaseDecodesSameKey},
      {"checksum tampering rejected", testChecksumTamperingRejected},
      {"wrong word count rejected", testWrongWordCountRejected},
      {"unknown words rejected", testUnknownWordsRejected},
      {"checksum word derivation", testChecksumWordDerivation},
      {"empty phrase rejected", testEmptyPhraseRejected},
  };

  int failures = 0;
  for (const auto &test : tests) {
    const int before = g_failures;
    std::printf("RUN  %s\n", test.name);
    test.fn();
    if (g_failures == before) {
      std::printf("PASS %s\n", test.name);
    } else {
      std::printf("FAIL %s\n", test.name);
      failures++;
    }
  }

  if (failures > 0) {
    std::printf("\n%d test(s) failed\n", failures);
    return EXIT_FAILURE;
  }

  std::printf("\nAll %zu tests passed\n", sizeof(tests) / sizeof(tests[0]));
  return EXIT_SUCCESS;
}
