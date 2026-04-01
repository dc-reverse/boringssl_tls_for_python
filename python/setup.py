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

# Determine paths
python_dir = Path(__file__).parent.resolve()
project_root = python_dir.parent

# BoringSSL paths - check environment variables first, then default locations
boringssl_root = project_root / "third_party" / "boringssl"
boringssl_install = boringssl_root / "install"

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

# Source files
sources = [
    python_dir / "src" / "tls_fingerprint_config.cc",
    python_dir / "src" / "tls_fingerprint_generator.cc",
    python_dir / "tls_fingerprint" / "_bindings.cc",
]

# Include directories
include_dirs = [
    python_dir / "include",
    Path(boringssl_include),
]

# Try to get pybind11 include
try:
    import pybind11
    include_dirs.append(Path(pybind11.get_include()))
    include_dirs.append(Path(pybind11.get_include(user=True)))
except ImportError:
    pass

# Library directories
library_dirs = [Path(boringssl_lib)]

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
    # On Windows, the libs are named ssl.lib and crypto.lib
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

# Filter existing source files
existing_sources = [str(s) for s in sources if s.exists()]
missing_sources = [s for s in sources if not s.exists()]
if missing_sources:
    print(f"WARNING: Missing source files: {missing_sources}")

# Filter existing include directories
existing_include_dirs = [str(d) for d in include_dirs if d.exists()]
if not existing_include_dirs:
    print("ERROR: No include directories found!")
elif len(existing_include_dirs) < len(include_dirs):
    missing_includes = [str(d) for d in include_dirs if not d.exists()]
    print(f"WARNING: Missing include directories: {missing_includes}")

# Filter existing library directories
existing_library_dirs = [str(d) for d in library_dirs if d.exists()]
if not existing_library_dirs:
    print("ERROR: No library directories found!")
    print(f"Expected: {library_dirs}")

# Define the extension
ext_modules = [
    Extension(
        "tls_fingerprint._tls_fingerprint",
        sources=existing_sources,
        include_dirs=existing_include_dirs,
        library_dirs=existing_library_dirs,
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
