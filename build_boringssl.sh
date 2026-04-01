#!/bin/bash
#
# Build BoringSSL for TLS Fingerprint Library
#
# Requirements:
#   - CMake 3.22+
#   - Ninja (recommended) or Make
#   - C++17 compiler (GCC 6.1+, Clang, or MSVC 2022+)
#
# Usage: ./build_boringssl.sh [--clean]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BORINGSSL_DIR="${SCRIPT_DIR}/third_party/boringssl"
BUILD_DIR="${SCRIPT_DIR}/build/boringssl"
INSTALL_DIR="${BORINGSSL_DIR}/install"

CLEAN=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=true
            shift
            ;;
    esac
done

# Detect platform
if [ "$(uname)" = "Darwin" ]; then
    PLATFORM="macos"
    CMAKE=/opt/homebrew/bin/cmake
    [ ! -x "$CMAKE" ] && CMAKE=cmake
elif [ "$(uname)" = "Linux" ]; then
    PLATFORM="linux"
    CMAKE=cmake
else
    echo "Unsupported platform: $(uname)"
    exit 1
fi

ARCH=$(uname -m)

echo "========================================"
echo "  Building BoringSSL"
echo "========================================"
echo "Platform: ${PLATFORM} ${ARCH}"
echo "Source: ${BORINGSSL_DIR}"
echo "Build: ${BUILD_DIR}"
echo "Install: ${INSTALL_DIR}"
echo ""

# Check CMake version
CMAKE_VERSION=$($CMAKE --version | head -1 | awk '{print $3}')
echo "CMake version: ${CMAKE_VERSION}"

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${INSTALL_DIR}"
fi

# Check BoringSSL source
if [ ! -f "${BORINGSSL_DIR}/CMakeLists.txt" ]; then
    echo "ERROR: BoringSSL source not found at ${BORINGSSL_DIR}"
    echo "Please ensure the repository was cloned correctly."
    exit 1
fi

# Create directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/include"

# Configure CMake
echo ""
echo "Configuring BoringSSL..."
cd "${BUILD_DIR}"

# Try Ninja first, fallback to Make
if command -v ninja &> /dev/null; then
    echo "Using Ninja generator..."
    $CMAKE "${BORINGSSL_DIR}" \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DOPENSSL_SMALL=1
    BUILD_CMD="ninja"
else
    echo "Using Unix Makefiles..."
    $CMAKE "${BORINGSSL_DIR}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DOPENSSL_SMALL=1
    BUILD_CMD="make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
fi

# Build
echo ""
echo "Building BoringSSL (this may take a few minutes)..."
eval $BUILD_CMD

# Install
echo ""
echo "Installing BoringSSL..."

# Copy libraries
if [ -f "libssl.a" ]; then
    cp libssl.a "${INSTALL_DIR}/lib/"
    cp libcrypto.a "${INSTALL_DIR}/lib/"
elif [ -f "ssl.lib" ]; then
    cp ssl.lib "${INSTALL_DIR}/lib/"
    cp crypto.lib "${INSTALL_DIR}/lib/"
else
    echo "ERROR: Could not find built libraries!"
    find . -name "*.a" -o -name "*.lib" 2>/dev/null | head -10
    exit 1
fi

# Copy headers
cp -r "${BORINGSSL_DIR}/include/"* "${INSTALL_DIR}/include/"

echo ""
echo "========================================"
echo "  BoringSSL Build Complete!"
echo "========================================"
echo ""
echo "Libraries:"
ls -lh "${INSTALL_DIR}/lib/"
echo ""
echo "Headers: ${INSTALL_DIR}/include/"
echo ""
echo "Next step: Build Python wheel"
echo "  cd python"
echo "  pip install pybind11"
echo "  python setup.py bdist_wheel"
echo ""
