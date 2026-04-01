#!/bin/bash
#
# Build BoringSSL for TLS Fingerprint Library
#
# This script compiles BoringSSL as a static library for use with the
# Python C++ extension.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BORINGSSL_DIR="${SCRIPT_DIR}/third_party/boringssl"
BUILD_DIR="${SCRIPT_DIR}/build/boringssl"
INSTALL_DIR="${SCRIPT_DIR}/third_party/boringssl/install"

# Detect platform
if [ "$(uname)" = "Darwin" ]; then
    PLATFORM="macos"
elif [ "$(uname)" = "Linux" ]; then
    PLATFORM="linux"
else
    echo "Unsupported platform"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)

echo "Building BoringSSL for ${PLATFORM} ${ARCH}..."

# Create build directory
mkdir -p "${BUILD_DIR}"
mkdir -p "${INSTALL_DIR}"

# Configure CMake
cd "${BUILD_DIR}"
cmake "${BORINGSSL_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_CXX_FLAGS="-std=c++17" \
    ${PLATFORM_EXTRA_FLAGS}

# Build
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Install
make install

echo "BoringSSL built successfully at ${INSTALL_DIR}"
echo "Libraries: ${INSTALL_DIR}/lib"
echo "Headers: ${INSTALL_DIR}/include"
