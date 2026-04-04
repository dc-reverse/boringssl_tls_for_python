#!/bin/bash
#
# TLS Fingerprint Library Build Script for Python
#
# Usage: ./build.sh [options]
#
# Options:
#   --release       Build in release mode (default)
#   --debug         Build in debug mode
#   --clean         Clean build directory before building
#   --test          Run tests after building
#   --install       Install Python package after building
#   --wheel-only    Build only Python wheel (skip CMake)
#   --cibuildwheel  Build wheels for all platforms using cibuildwheel (requires Docker on Linux)
#   --help          Show this help message
#
# Multi-platform builds:
#   For building wheels for multiple platforms (macOS Intel/ARM, Windows, Linux),
#   use: ./build.sh --cibuildwheel
#   Or use GitHub Actions: push a tag like 'v1.0.0' to trigger automatic builds.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BUILD_TYPE="Release"
CLEAN=false
RUN_TESTS=false
INSTALL=false
WHEEL_ONLY=false
USE_CIBUILDWHEEL=false
BUILD_DIR="build"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --test)
            RUN_TESTS=true
            shift
            ;;
        --install)
            INSTALL=true
            shift
            ;;
        --wheel-only)
            WHEEL_ONLY=true
            shift
            ;;
        --cibuildwheel)
            USE_CIBUILDWHEEL=true
            shift
            ;;
        --help)
            echo "TLS Fingerprint Library Build Script for Python"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --release       Build in release mode (default)"
            echo "  --debug         Build in debug mode"
            echo "  --clean         Clean build directory before building"
            echo "  --test          Run tests after building"
            echo "  --install       Install Python package after building"
            echo "  --wheel-only    Build only Python wheel (skip CMake)"
            echo "  --cibuildwheel  Build wheels for all platforms using cibuildwheel"
            echo "  --help          Show this help message"
            echo ""
            echo "Multi-platform builds:"
            echo "  Use --cibuildwheel to build for macOS (Intel/ARM), Windows, Linux"
            echo "  Or push a git tag (v*) to trigger GitHub Actions builds"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect Python: prefer venv, then system python3
if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python3"
    PIP="$SCRIPT_DIR/.venv/bin/pip"
elif [ -f "$SCRIPT_DIR/python/.venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/python/.venv/bin/python3"
    PIP="$SCRIPT_DIR/python/.venv/bin/pip"
elif command -v python3 &> /dev/null; then
    PYTHON="python3"
    PIP="pip3"
else
    echo -e "${RED}Python3 not found${NC}"
    exit 1
fi
echo -e "${YELLOW}Using Python: $PYTHON${NC}"

# cibuildwheel mode
if [ "$USE_CIBUILDWHEEL" = true ]; then
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Multi-Platform Build with cibuildwheel${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    # Check cibuildwheel
    if ! command -v cibuildwheel &> /dev/null; then
        echo -e "${YELLOW}Installing cibuildwheel...${NC}"
        pip3 install cibuildwheel
    fi

    echo -e "${YELLOW}Building wheels for all platforms...${NC}"
    echo "This may take a while. Docker is required for Linux builds."
    echo ""

    cd "$SCRIPT_DIR/python"
    cibuildwheel --output-dir wheelhouse

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Multi-Platform Build Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Output wheels:"
    ls -la wheelhouse/*.whl
    echo ""
    echo "To upload to PyPI:"
    echo "  pip install twine"
    echo "  twine upload wheelhouse/*.whl"
    echo ""
    exit 0
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  TLS Fingerprint Library Build (Python)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Build Type: $BUILD_TYPE"
echo "  Build Dir:  $BUILD_DIR"
echo "  Jobs:       $JOBS"
echo "  Clean:      $CLEAN"
echo "  Run Tests:  $RUN_TESTS"
echo "  Install:    $INSTALL"
echo "  Wheel Only: $WHEEL_ONLY"
echo ""

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
    rm -rf python/dist
    rm -rf python/build
    rm -rf python/*.egg-info
    echo -e "${GREEN}Clean complete.${NC}"
    echo ""
fi

# Create build directory
mkdir -p "$BUILD_DIR"

STEP_NUM=1

# Step 1: Configure CMake (skip if wheel-only)
if [ "$WHEEL_ONLY" = false ]; then
    echo -e "${YELLOW}Step $STEP_NUM: Configuring CMake...${NC}"
    cd "$BUILD_DIR"
    cmake .. \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DBUILD_PYTHON_BINDINGS=ON \
        -DBUILD_TESTS=$( [ "$RUN_TESTS" = true ] && echo "ON" || echo "OFF" ) \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DPython3_EXECUTABLE="$PYTHON"

    echo -e "${GREEN}CMake configuration complete.${NC}"
    echo ""

    STEP_NUM=$((STEP_NUM + 1))

    # Step 2: Build native library
    echo -e "${YELLOW}Step $STEP_NUM: Building native library...${NC}"
    cmake --build . --config "$BUILD_TYPE" --parallel "$JOBS"
    echo -e "${GREEN}Native library build complete.${NC}"
    echo ""

    STEP_NUM=$((STEP_NUM + 1))
fi

# Step 3: Build Python wheel package
echo -e "${YELLOW}Step $STEP_NUM: Building Python wheel package...${NC}"
cd "$SCRIPT_DIR/python"

# Clean previous builds
rm -rf dist/ build/ *.egg-info tls_fingerprint/*.egg-info

# Build wheel
$PYTHON setup.py bdist_wheel 2>/dev/null || {
    echo -e "${RED}Failed to build wheel package${NC}"
    exit 1
}

# Check output
if ls dist/*.whl 2>/dev/null; then
    echo -e "${GREEN}Wheel package created successfully${NC}"
    ls -lh dist/*.whl
else
    echo -e "${RED}Wheel package not found${NC}"
    exit 1
fi

echo ""

STEP_NUM=$((STEP_NUM + 1))

# Step 4: Run tests if requested
if [ "$RUN_TESTS" = true ]; then
    echo -e "${YELLOW}Step $STEP_NUM: Running tests...${NC}"

    # Run C++ tests
    if [ "$WHEEL_ONLY" = false ]; then
        cd "$SCRIPT_DIR/$BUILD_DIR"
        if [ -f "ctest" ]; then
            ctest --output-on-failure --build-config "$BUILD_TYPE" || {
                echo -e "${RED}C++ tests failed${NC}"
                exit 1
            }
        fi
    fi

    # Run Python tests
    cd "$SCRIPT_DIR"
    if [ -d "tests/python" ]; then
        $PIP install --quiet pytest
        $PYTHON -m pytest tests/python/ -v || {
            echo -e "${RED}Python tests failed${NC}"
            exit 1
        }
    fi

    echo -e "${GREEN}All tests passed.${NC}"
    echo ""

    STEP_NUM=$((STEP_NUM + 1))
fi

# Step 5: Install if requested
if [ "$INSTALL" = true ]; then
    echo -e "${YELLOW}Step $STEP_NUM: Installing Python package...${NC}"
    cd "$SCRIPT_DIR/python"

    $PIP install dist/*.whl --force-reinstall || {
        echo -e "${RED}Failed to install Python package${NC}"
        exit 1
    }

    echo -e "${GREEN}Python package installed successfully.${NC}"
    echo ""

    # Verify installation
    echo -e "${YELLOW}Verifying installation...${NC}"
    $PYTHON -c "import tls_fingerprint; print(f'tls_fingerprint version: {tls_fingerprint.__version__}')" || {
        echo -e "${RED}Verification failed${NC}"
        exit 1
    }
    echo -e "${GREEN}Verification successful.${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Output files:"
if [ "$WHEEL_ONLY" = false ]; then
    echo "  - Native library: $BUILD_DIR/libtls_fingerprint*"
fi
echo "  - Python wheel:   python/dist/tls_fingerprint-*.whl"
echo ""

if [ "$INSTALL" = true ]; then
    echo -e "${GREEN}The package is now installed and ready to use.${NC}"
    echo ""
    echo "Quick start:"
    echo "  from tls_fingerprint import BrowserFingerprints, TLSHttpClient"
    echo "  config = BrowserFingerprints.chrome_desktop()"
    echo "  client = TLSHttpClient(config)"
else
    echo "To install the Python package:"
    echo "  pip install python/dist/tls_fingerprint-*.whl"
fi
echo ""
echo "For multi-platform builds:"
echo "  ./build.sh --cibuildwheel"
echo ""
