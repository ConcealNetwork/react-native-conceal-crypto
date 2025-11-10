# react-native-conceal-crypto

A React Native library providing native C++ crypto utilities for Conceal blockchain, built with Nitro JSI modules.  
Includes both basic encryption and advanced elliptic curve cryptography.

## Features

- **ChaCha8/ChaCha12 encryption** - Fast symmetric encryption algorithms
- **libsodium secretbox** - Authenticated encryption with XSalsa20-Poly1305
- **HMAC-SHA1** - Message authentication for TOTP computation
- **Cryptonote elliptic curve operations** - Complete blockchain crypto primitives
- **Mnemonics encoding/decoding** - Native C++ implementation for 25-word English mnemonic phrases
- **Hex conversion** - Convert between hex strings and binary data
- **Cryptographically secure random** - Generate random data and mnemonic-style strings
- **Zero-copy ArrayBuffer** - High-performance binary data handling

## API Reference

### Encryption & Decryption
- `chacha8(input, key, iv)` - ChaCha8 stream cipher encryption
- `chacha12(input, key, iv)` - ChaCha12 stream cipher encryption  
- `secretbox(message, nonce, key)` - Authenticated encryption (XSalsa20-Poly1305)
- `secretboxOpen(ciphertext, nonce, key)` - Authenticated decryption (returns null on failure)

### Cryptonote Elliptic Curve Operations (Performance Optimized)
- `cryptonote.generateKeyDerivation(publicKey, secretKey)` - Generate key derivation (32-byte ArrayBuffer) ⚡
- `cryptonote.derivePublicKey(derivation, outputIndex, publicKey)` - Derive public key (32-byte ArrayBuffer) ⚡
- `cryptonote.geScalarmult(publicKey, secretKey)` - Scalar multiplication (32-byte ArrayBuffer) ⚡
- `cryptonote.geAdd(point1, point2)` - Add two elliptic curve points (32-byte ArrayBuffer) ⚡
- `cryptonote.geScalarmultBase(secretKey)` - Scalar multiplication with base point (32-byte ArrayBuffer) ⚡
- `cryptonote.geDoubleScalarmultBaseVartime(c, P, r)` - Double scalar multiplication c*P + r*G (32-byte ArrayBuffer) ⚡
- `cryptonote.geDoubleScalarmultPostcompVartime(r, P, c, I)` - Double scalar multiplication r*Pb + c*I (32-byte ArrayBuffer) ⚡

**Performance Features:**
- ⚡ **constexpr** validation for compile-time optimization
- ⚡ **Static thread-local buffers** to eliminate repeated allocations
- ⚡ **Zero-copy ArrayBuffer** operations for maximum speed
- ⚡ **Memory pre-allocation** for frequently called functions
- ⚡ **Inline functions** to reduce call overhead

### Data Conversion
- `hextobin(hex)` - Convert hex string to ArrayBuffer
- `bintohex(buffer)` - Convert ArrayBuffer to hex string

### Random Generation
- `random(bits)` - Generate cryptographically secure random string
- `randomBytes(bytes)` - Generate random bytes as ArrayBuffer

### Authentication
- `hmacSha1(key, data)` - HMAC-SHA1 message authentication

### Mnemonics (English Only)
- `mnemonics.mn_encode(privateKeyHex)` - Encode a private key (64-char hex string) into a 25-word mnemonic phrase
- `mnemonics.mn_decode(mnemonicPhrase)` - Decode a 25-word mnemonic phrase back to a private key (64-char hex string)

**Note:** Only English language is supported. The mnemonic phrase must be exactly 25 words with a valid checksum.

## Installation

```bash
npm pack
npm install file:react-native-conceal-crypto-0.x.x.tgz

```

## Usage

```typescript
import concealCrypto from 'react-native-conceal-crypto';

// Convert hex to binary
const buffer = concealCrypto.hextobin('deadbeef');

// Encrypt data with ChaCha8
const encrypted = concealCrypto.chacha8(input, key, iv);

// Authenticated encryption with libsodium
const ciphertext = concealCrypto.secretbox(message, nonce, key);
const decrypted = concealCrypto.secretboxOpen(ciphertext, nonce, key);

// Generate random data
const randomStr = concealCrypto.random(256);
const randomBytes = concealCrypto.randomBytes(32);

// Cryptonote elliptic curve operations (optimized with ArrayBuffer)
const publicKeyBuf = concealCrypto.hextobin(publicKeyHex);
const secretKeyBuf = concealCrypto.hextobin(secretKeyHex);
const derivation = concealCrypto.cryptonote.generateKeyDerivation(publicKeyBuf, secretKeyBuf);
const derivedKey = concealCrypto.cryptonote.derivePublicKey(derivation, 0, publicKeyBuf);
const scalarMult = concealCrypto.cryptonote.geScalarmult(publicKeyBuf, secretKeyBuf);
const pointSum = concealCrypto.cryptonote.geAdd(point1Buf, point2Buf);
const baseMult = concealCrypto.cryptonote.geScalarmultBase(secretKeyBuf);
const doubleMult = concealCrypto.cryptonote.geDoubleScalarmultBaseVartime(cBuf, PBuf, rBuf);
const postcompMult = concealCrypto.cryptonote.geDoubleScalarmultPostcompVartime(rBuf, PBuf, cBuf, IBuf);

// Convert binary to hex
const hex = concealCrypto.bintohex(buffer);

// Mnemonics encoding/decoding (English only)
const privateKeyHex = 'a1b2c3d4e5f6...'; // 64-character hex string
const mnemonic = concealCrypto.mnemonics.mn_encode(privateKeyHex);
// Returns: "word1 word2 word3 ... word25" (25 words)

const decodedKey = concealCrypto.mnemonics.mn_decode(mnemonic);
// Returns: original 64-character hex string
```

## Integrating Nitro in your app (Android)

In some setups (especially local development with Nitro), you may need small scripts to ensure Gradle picks up Nitro and to initialize the module at app start.

### 1) Ensure Nitro is included in `settings.gradle`

If your app uses Expo config plugins or you generate config at build time, add in plugin section of `app.config.ts`, a script like ` './scripts/withNitroModulesPlugin',` to append the `react-native-nitro-modules` include when missing:

```js
// app.config.ts
const { withSettingsGradle } = require('@expo/config-plugins');

module.exports = function withNitroModulesPlugin(config) {
  return withSettingsGradle(config, (cfg) => {
    const nitroBlock = `
include(":react-native-nitro-modules")
project(":react-native-nitro-modules").projectDir = new File(rootProject.projectDir, "../node_modules/react-native-nitro-modules/android")
`;
    if (!cfg.modResults.contents.includes('react-native-nitro-modules')) {
      cfg.modResults.contents += `\n// Added by withNitroModulesPlugin\n${nitroBlock}`;
    }
    return cfg;
  });
};
```

Run this before building (or as part of your build pipeline) so Gradle resolves the Nitro Android project correctly.

### 2) Initialize the Nitro module in `MainApplication.kt`

Some projects benefit from explicitly calling the Nitro OnLoad initializer in the app's `onCreate()`. You can automate the insertion with a small Node script:

```js
// scripts/patch-mainapplication-nitro.js
const fs = require('fs');
const path = require('path');

// Path to your parent app's MainApplication.kt
const MAIN_APP_PATH = path.join(
  __dirname,
  '..',
  'android',
  'app',
  'src',
  'main',
  'java',
  'com',
  'acktarius',
  'conceal2faapp',
  'MainApplication.kt'
);

// Nitro module Kotlin OnLoad path
const NITRO_INIT_PACKAGE = 'com.margelo.nitro.concealcrypto';
const NITRO_INIT_CLASS = 'ConcealCryptoOnLoad';
const NITRO_IMPORT = `import ${NITRO_INIT_PACKAGE}.${NITRO_INIT_CLASS}`;
const NITRO_INIT_CALL = `${NITRO_INIT_CLASS}.initializeNative()`;

function insertInit(source) {
  let result = source;
  if (!result.includes(NITRO_IMPORT)) {
    result = result.replace(/(package .+?\n)/, `$1${NITRO_IMPORT}\n`);
  }
  if (!result.includes(NITRO_INIT_CALL)) {
    result = result.replace(
      /(override fun onCreate\(\)\s*\{\s*super\.onCreate\(\);?)/,
      `$1\n        ${NITRO_INIT_CALL}`
    );
  }
  return result;
}

fs.readFile(MAIN_APP_PATH, 'utf8', (err, data) => {
  if (err) {
    console.error('❌ Could not find MainApplication.kt:', err.message);
    return;
  }
  const updated = insertInit(data);
  fs.writeFile(MAIN_APP_PATH, updated, 'utf8', (err) => {
    if (err) {
      console.error('❌ Failed to update MainApplication.kt:', err.message);
    } else {
      console.log('✅ ConcealCryptoOnLoad.initializeNative() added successfully!');
    }
  });
});
```

Tip: run these scripts after a clean and before building (e.g., in CI or `prebuild`) to keep your app stable when Nitro is a local dependency.

## License

MIT
