cmake_minimum_required(VERSION 3.10.2)
project(ConcealCrypto)

# Compiler setup
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)


# Library name must match androidCxxLibName in nitro.json
set(PACKAGE_NAME ConcealCrypto)

#---------------------------------------------
# 1. Add your native sources
#---------------------------------------------
add_library(${PACKAGE_NAME} SHARED
  ../cpp/install.cpp
  ../cpp/HybridConcealCrypto.cpp
  ../cpp/HybridCryptonote.cpp
  ../cpp/HybridMnemonics.cpp
  ../cpp/Hmac.cpp
  ../cpp/chacha8.c
  ../cpp/chacha12.c
  ../cpp/mn_random.cpp
  ../cpp/Cryptonote/crypto.cpp
  ../cpp/Cryptonote/crypto-ops.c
  ../cpp/Cryptonote/crypto-ops-data.c
  ../cpp/Cryptonote/hash.c
  ../cpp/Cryptonote/keccak.c
  ../cpp/Mnemonics/Mnemonics.cpp
  ../cpp/Mnemonics/CRC32.cpp
  # Note: random.c not needed - we use libsodium via randombytes_buf() instead
)

#---------------------------------------------
# 2. Include directories for headers
#---------------------------------------------
include_directories(
  ../cpp
  ../cpp/Cryptonote
  ../cpp/Mnemonics
  ../nitrogen/generated/shared/c++
  ${CMAKE_SOURCE_DIR}/../node_modules/react-native-nitro-modules/cpp
)

#---------------------------------------------
# 3. Include Nitrogen‑generated autolinking setup
#---------------------------------------------
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/ConcealCrypto+autolinking.cmake)
#---------------------------------------------
# 4. Find system libraries
#---------------------------------------------
find_library(LOG_LIB log)

#---------------------------------------------
# Try to find libsodium using modern CMake approaches
#---------------------------------------------

# Option 1: Try system-installed libsodium first
find_package(Sodium QUIET)
if(Sodium_FOUND)
    target_link_libraries(${PACKAGE_NAME} PRIVATE sodium)
    target_compile_definitions(${PACKAGE_NAME} PRIVATE HAVE_SODIUM_H=1)
    message(STATUS "libsodium found (system) - using OS CSPRNG")
else()
    # Option 2: Try pkg-config as fallback
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBSODIUM libsodium)
        if(LIBSODIUM_FOUND)
            target_link_libraries(${PACKAGE_NAME} PRIVATE ${LIBSODIUM_LIBRARIES})
            target_include_directories(${PACKAGE_NAME} PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
            target_compile_definitions(${PACKAGE_NAME} PRIVATE HAVE_SODIUM_H=1)
            message(STATUS "libsodium found (pkg-config) - using OS CSPRNG")
        else()
            message(STATUS "libsodium not found - using hardware RNG fallback")
        endif()
    else()
        message(STATUS "pkg-config not found - using hardware RNG fallback")
    endif()
endif()

# Option 3: FetchContent approach (for Android builds without system libsodium)
include(FetchContent)
FetchContent_Declare(
  Sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
)
FetchContent_MakeAvailable(Sodium)
# Use plain signature (no PRIVATE) to match autolinking.cmake
target_link_libraries(${PACKAGE_NAME} sodium)
target_include_directories(${PACKAGE_NAME} PRIVATE ${SODIUM_INCLUDE_DIRS})
target_compile_definitions(${PACKAGE_NAME} PRIVATE HAVE_SODIUM_H=1)

#---------------------------------------------
# 5. Link everything
#---------------------------------------------
target_link_libraries(
  ${PACKAGE_NAME}
  ${LOG_LIB}        # Android logcat logger
  android           # JNI core
  # fbjni::fbjni     # Only if autolinking didn't add it
  # ReactAndroid::jsi # Usually auto‑linked by Nitro
  # openssl::crypto  # Uncomment if OpenSSL added
)
