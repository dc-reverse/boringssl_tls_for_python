"""
Setup script for TLS Fingerprint Library - Python Package
Supports: macOS (Intel/ARM), Windows (MSVC), Linux (GCC)
Uses BoringSSL for TLS fingerprint generation
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages, Extension

# Determine paths - use relative paths for setuptools compatibility
python_dir = Path(__file__).parent.resolve()

# BoringSSL paths - relative to python directory
boringssl_install = python_dir.parent / "third_party" / "boringssl" / "install"

# Environment variables take precedence (for cibuildwheel)
boringssl_include = os.environ.get(
    "BORINGSSL_INCLUDE",
    str(boringssl_install / "include")
)
boringssl_lib = os.environ.get(
    "BORINGSSL_LIB",
    str(boringssl_install / "lib")
)

print(f"BoringSSL include: {boringssl_include}")
print(f"BoringSSL lib: {boringssl_lib}")

# Source files - use relative paths
sources = [
    "src/tls_fingerprint_config.cc",
    "src/tls_fingerprint_generator.cc",
    "src/boringssl_socket.cc",
    "tls_fingerprint/_bindings.cc",
]

# Include directories
include_dirs = [
    "include",
    boringssl_include,
]

# Try to get pybind11 include
try:
    import pybind11
    include_dirs.append(pybind11.get_include())
    include_dirs.append(pybind11.get_include(user=True))
except ImportError:
    pass

# Library directories
library_dirs = [boringssl_lib]

# Platform-specific configuration
if sys.platform == "darwin":
    # macOS - Clang
    extra_compile_args = [
        "-std=c++17",
        "-O3",
        "-fPIC",
        "-stdlib=libc++",
        "-mmacosx-version-min=10.14",
        "-DNDEBUG",
    ]
    extra_link_args = ["-Wl,-dead_strip"]
    libraries = ["ssl", "crypto"]

elif sys.platform == "win32":
    # Windows - MSVC
    extra_compile_args = [
        "/std:c++17",
        "/O2",
        "/EHsc",
        "/DNDEBUG",
        "/MD",
    ]
    extra_link_args = []
    libraries = ["ssl", "crypto", "ws2_32", "advapi32", "crypt32"]

else:
    # Linux - GCC
    extra_compile_args = [
        "-std=c++17",
        "-O3",
        "-fPIC",
        "-DNDEBUG",
    ]
    extra_link_args = ["-static-libstdc++", "-static-libgcc"]
    libraries = ["ssl", "crypto", "pthread", "dl"]

# Check if required files exist
boringssl_include_path = Path(boringssl_include)
boringssl_lib_path = Path(boringssl_lib)

if not boringssl_include_path.exists():
    print(f"ERROR: BoringSSL include directory not found: {boringssl_include}")
    print("Please build BoringSSL first or set BORINGSSL_INCLUDE environment variable")

if not boringssl_lib_path.exists():
    print(f"ERROR: BoringSSL lib directory not found: {boringssl_lib}")
    print("Please build BoringSSL first or set BORINGSSL_LIB environment variable")

# Define the extension
ext_modules = [
    Extension(
        "tls_fingerprint._tls_fingerprint",
        sources=sources,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        language="c++",
    )
]

# Read README
readme = python_dir / "README.md"
long_desc = readme.read_text() if readme.exists() else ""

setup(
    name="tls-fingerprint",
    version="1.0.0",
    description="Chromium-based TLS fingerprint library using BoringSSL",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests*", "build*", "dist*"]),
    ext_modules=ext_modules,
    package_data={"tls_fingerprint": ["*.py", "py.typed"]},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.8",
    install_requires=["requests>=2.28.0"],
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C++",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Operating System :: OS Independent",
    ],
)
