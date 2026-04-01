"""
Setup script for TLS Fingerprint Library - Python Package
Supports: macOS (Intel/ARM), Windows (MSVC), Linux (GCC)
Uses BoringSSL for TLS fingerprint generation
"""

import os
import sys
import platform
from pathlib import Path
from setuptools import setup, find_packages, Extension

# Determine paths - use local files for cibuildwheel compatibility
python_dir = Path(__file__).parent.resolve()

# Source files (local copies for cibuildwheel)
sources = [
    python_dir / "src" / "tls_fingerprint_config.cc",
    python_dir / "src" / "tls_fingerprint_generator.cc",
    python_dir / "tls_fingerprint" / "_bindings.cc",
]

# Verify sources exist
missing = [s for s in sources if not s.exists()]
if missing:
    print(f"WARNING: Missing source files: {missing}")

# Include directories
include_dirs = [
    python_dir / "include",
]

# Try to get pybind11 include
try:
    import pybind11
    include_dirs.append(pybind11.get_include())
    include_dirs.append(pybind11.get_include(user=True))
except ImportError:
    pass

# Platform-specific compiler and linker flags
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

else:
    # Linux - GCC
    extra_compile_args = [
        "-std=c++17",
        "-O3",
        "-fPIC",
        "-DNDEBUG",
    ]
    # Statically link libstdc++ and libgcc for portability
    extra_link_args = ["-static-libstdc++", "-static-libgcc"]

# Define the extension
ext_modules = [
    Extension(
        "tls_fingerprint._tls_fingerprint",
        sources=[str(s) for s in sources],
        include_dirs=[str(d) for d in include_dirs],
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
