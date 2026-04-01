"""
Setup script for TLS Fingerprint Library - Python Package
Supports: macOS (Intel/ARM), Windows (MSVC), Linux (GCC)
Uses BoringSSL for TLS fingerprint generation
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext as _build_ext

# Determine paths
python_dir = Path(__file__).parent.resolve()
project_root = python_dir.parent

# BoringSSL paths - check environment variables first, then default locations
boringssl_include = os.environ.get(
    "BORINGSSL_INCLUDE",
    str(project_root / "third_party" / "boringssl" / "install" / "usr" / "local" / "include")
)
boringssl_lib = os.environ.get(
    "BORINGSSL_LIB",
    str(project_root / "third_party" / "boringssl" / "install" / "usr" / "local" / "lib")
)

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

# Libraries to link
libraries = ["ssl", "crypto"]


class BuildExt(_build_ext):
    """Custom build extension to handle BoringSSL compilation."""

    def run(self):
        # Check if BoringSSL is built
        boringssl_lib_path = Path(boringssl_lib)
        if not boringssl_lib_path.exists():
            print("=" * 60)
            print("WARNING: BoringSSL not found at", boringssl_lib_path)
            print("Please build BoringSSL first:")
            print("  ./build_boringssl.sh")
            print("Or set environment variables:")
            print("  BORINGSSL_INCLUDE=/path/to/include")
            print("  BORINGSSL_LIB=/path/to/lib")
            print("=" * 60)
            # Try to build BoringSSL automatically
            self._build_boringssl()

        # Run the standard build
        super().run()

    def _build_boringssl(self):
        """Attempt to build BoringSSL automatically."""
        boringssl_dir = project_root / "third_party" / "boringssl"
        build_dir = project_root / "build" / "boringssl"
        install_dir = boringssl_dir / "install"

        if not boringssl_dir.exists():
            print("BoringSSL source not found, skipping...")
            return

        print("Attempting to build BoringSSL...")

        # Create build directory
        build_dir.mkdir(parents=True, exist_ok=True)

        # Configure
        cmake_cmd = [
            "cmake",
            str(boringssl_dir),
            f"-DCMAKE_INSTALL_PREFIX={install_dir / 'usr' / 'local'}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DBUILD_SHARED_LIBS=OFF",
        ]

        if sys.platform == "win32":
            cmake_cmd.extend(["-G", "Visual Studio 17 2022", "-A", "x64"])
        else:
            cmake_cmd.extend(["-G", "Unix Makefiles"])

        try:
            subprocess.run(cmake_cmd, cwd=build_dir, check=True)

            # Build
            if sys.platform == "win32":
                subprocess.run(
                    ["cmake", "--build", ".", "--config", "Release", "--target", "install"],
                    cwd=build_dir,
                    check=True
                )
            else:
                subprocess.run(["make", "-j4", "install"], cwd=build_dir, check=True)

            print("BoringSSL built successfully!")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to build BoringSSL: {e}")
            print("Please build BoringSSL manually.")


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
    extra_link_args = ["-static-libstdc++", "-static-libgcc"]


# Filter existing source files
existing_sources = [str(s) for s in sources if s.exists()]
missing_sources = [s for s in sources if not s.exists()]
if missing_sources:
    print(f"WARNING: Missing source files: {missing_sources}")

# Filter existing include directories
existing_include_dirs = [str(d) for d in include_dirs if d.exists()]
existing_library_dirs = [str(d) for d in library_dirs if d.exists()]

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
    cmdclass={"build_ext": BuildExt},
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
