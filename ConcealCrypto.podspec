require 'json'
package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

# Single source of truth for the pinned libsodium release (prepare_command,
# source_files, and HEADER_SEARCH_PATHS all interpolate this).
libsodium_version = '1.0.20'
libsodium_sha256 = 'ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19'

Pod::UI.puts "[ConcealCrypto] 🔐 Cryptonote crypto powered by C++"

Pod::Spec.new do |s|
  s.name         = 'ConcealCrypto'  # Match iosModuleName from nitro.json
  s.version      = package['version']
  s.summary      = package['description']
  s.homepage     = package['homepage']
  s.license      = package['license']
  s.author       = package['author']
  s.platforms    = { :ios => '15.1' }
  s.ios.deployment_target = '15.1'
  s.source       = { :git => package['repository']['url'], :tag => "v#{s.version}" }

  # Build libsodium from source (avoids CocoaPods header pollution)
  # <<-CMD interpolates Ruby #{} so the version/checksum stay single-sourced.
  s.prepare_command = <<-CMD
    set -e  # Exit on any error
    set -x  # Print commands as they execute

    # Create ios directory if it doesn't exist
    mkdir -p ios

    # Pin the exact release tarball (the -stable URL is a mutable alias that
    # can silently change upstream) and verify its SHA-256 before building.

    # Download libsodium with verbose output
    echo "Downloading libsodium #{libsodium_version}..."
    curl -f -L -v -o ios/libsodium.tar.gz "https://download.libsodium.org/libsodium/releases/libsodium-#{libsodium_version}.tar.gz"

    # Verify download
    if [ ! -f ios/libsodium.tar.gz ]; then
      echo "ERROR: Failed to download libsodium.tar.gz"
      exit 1
    fi

    echo "Download size: $(wc -c < ios/libsodium.tar.gz) bytes"

    # Verify checksum (shasum ships with macOS; a mismatch aborts pod install)
    echo "Verifying libsodium checksum..."
    echo "#{libsodium_sha256}  ios/libsodium.tar.gz" | shasum -a 256 -c -

    # Clean previous extraction
    rm -rf "ios/libsodium-#{libsodium_version}"

    # Extract the full tarball
    echo "Extracting libsodium..."
    tar -xzf ios/libsodium.tar.gz -C ios

    # Verify extraction
    if [ ! -d "ios/libsodium-#{libsodium_version}" ]; then
      echo "ERROR: Failed to extract libsodium"
      exit 1
    fi

    # Run configure and make to generate all headers including private ones
    echo "Configuring libsodium..."
    cd "ios/libsodium-#{libsodium_version}"
    ./configure --disable-shared --enable-static
    
    echo "Building libsodium..."
    make -j$(sysctl -n hw.ncpu)
    
    # Verify build success
    if [ ! -f src/libsodium/.libs/libsodium.a ]; then
      echo "ERROR: libsodium build failed - static library not found"
      exit 1
    fi
    
    echo "libsodium build completed successfully"

    # Cleanup
    cd ../../
    rm -f ios/libsodium.tar.gz
  CMD

  # C++ implementation files (matching CMakeLists.txt structure)
  s.source_files = [
    'cpp/**/*.{h,hpp,cpp,c,mm}',
    "ios/libsodium-#{libsodium_version}/src/libsodium/**/*.{h,c}",
  ]

  # iOS-specific compiler settings (set BEFORE nitrogen autolinking)
  sodium_headers = [
    "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-#{libsodium_version}/src/libsodium/include\"",
    "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-#{libsodium_version}/src/libsodium/include/sodium\"",
    "\"$(PODS_TARGET_SRCROOT)/ios/libsodium-#{libsodium_version}\"",
    "\"$(PODS_ROOT)/../../packages/react-native-conceal-crypto/ios/libsodium-#{libsodium_version}/src/libsodium/include\"",
    "\"$(PODS_ROOT)/../../packages/react-native-conceal-crypto/ios/libsodium-#{libsodium_version}/src/libsodium/include/sodium\""
  ]
  
  xcconfig = {
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++20',
    'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES',
    'HEADER_SEARCH_PATHS' => sodium_headers.join(' '),
    'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) BLSALLOC_SODIUM=1'
  }
  
  s.pod_target_xcconfig = xcconfig

  # Load Nitrogen autolinking (adds generated files + NitroModules dependency)
  # This will merge with pod_target_xcconfig set above
  load 'nitrogen/generated/ios/ConcealCrypto+autolinking.rb'
  add_nitrogen_files(s)

  # Dependencies
  s.dependency 'React-Core'
  
  install_modules_dependencies(s)
end
