"""
Setup script for TLS Fingerprint Library - Python Package
Supports: macOS (Intel/ARM), Windows (MSVC), Linux (GCC)
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages, Extension

# Determine paths
python_dir = Path(__file__).parent.resolve()
project_root = python_dir.parent

# Source files
sources = [
    str(project_root / "src" / "tls_fingerprint_config.cc"),
    str(project_root / "src" / "tls_fingerprint_generator.cc"),
    str(python_dir / "tls_fingerprint" / "_bindings.cc"),
]

# Include directories
include_dirs = [
    str(project_root / "include"),
]

# Try to get pybind11 include
try:
    import pybind11
    include_dirs.append(pybind11.get_include())
    include_dirs.append(pybind11.get_include(user=True))
except ImportError:
    pass

# Compiler flags
extra_compile_args = [
    "-std=c++17",
    "-O3",
    "-fPIC",
    "-DNDEBUG",
]

# Linker flags
extra_link_args = []

# Platform-specific settings
if sys.platform == "darwin":
    # macOS - use -stdlib=libc++ for compatibility
    extra_compile_args.append("-stdlib=libc++")
    extra_compile_args.append("-mmacosx-version-min=10.14")
    # Strip unused symbols
    extra_link_args.extend(["-Wl,-dead_strip"])
elif sys.platform == "win32":
    # Windows MSVC
    extra_compile_args = [
        "/std:c++17",
        "/O2",
        "/EHsc",
        "/DNDEBUG",
        "/MD",
    ]
    extra_link_args = []
elif sys.platform.startswith("linux"):
    # Linux - statically link libstdc++ and libgcc to avoid dependency issues
    extra_link_args.extend(["-static-libstdc++", "-static-libgcc"])

# Define the extension
ext_modules = [
    Extension(
        "tls_fingerprint._tls_fingerprint",
        sources=sources,
        include_dirs=include_dirs,
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
    description="Chromium-based TLS fingerprint library",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests*", "build*", "dist*"]),
    ext_modules=ext_modules,
    package_data={"tls_fingerprint": ["*.py"]},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
