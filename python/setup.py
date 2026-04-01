"""
Setup script for TLS Fingerprint Library - Python Package
Supports: macOS (Intel/ARM), Windows (MSVC), Linux (GCC)
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext as _build_ext


class BuildExt(_build_ext):
    """Build C++ extension with cross-platform support."""

    def run(self):
        for ext in self.extensions:
            self._build_extension(ext)

    def _build_extension(self, ext):
        python_dir = Path(__file__).parent
        project_root = python_dir.parent

        # Source files
        sources = [
            project_root / "src" / "tls_fingerprint_config.cc",
            project_root / "src" / "tls_fingerprint_generator.cc",
            python_dir / "tls_fingerprint" / "_bindings.cc",
        ]

        # Check sources exist
        missing = [s for s in sources if not s.exists()]
        if missing:
            print(f"C++ sources not found: {missing}")
            print("Using pure Python implementation")
            return

        # Include directories
        include_dirs = [project_root / "include"]

        # Try pybind11
        try:
            import pybind11
            include_dirs.append(Path(pybind11.get_include()))
        except ImportError:
            print("pybind11 not found")
            return

        # Add Python include
        import sysconfig
        py_inc = sysconfig.get_path('include')
        if py_inc:
            include_dirs.append(Path(py_inc))

        include_dirs = [d for d in include_dirs if d.exists()]

        # Output
        ext_filename = self.get_ext_filename(ext.name)
        output_path = Path(self.build_lib) / "tls_fingerprint" / ext_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"Building C++ extension for Python {sys.version_info.major}.{sys.version_info.minor} on {platform.system()}...")

        # Platform-specific build
        if sys.platform == "win32":
            success = self._build_windows(ext, sources, include_dirs, output_path)
        elif sys.platform == "darwin":
            success = self._build_macos(sources, include_dirs, output_path)
        else:  # Linux and other Unix-like systems
            success = self._build_linux(sources, include_dirs, output_path)

        if not success:
            print("Using pure Python implementation")

    def _build_windows(self, ext, sources, include_dirs, output_path):
        """Build using MSVC on Windows."""
        # Find MSVC compiler
        cmd = ["cl"]

        # Check if cl is available
        result = subprocess.run(["where", "cl"], capture_output=True, text=True)
        if result.returncode != 0:
            print("MSVC compiler (cl.exe) not found in PATH")
            print("Please run from Visual Studio Developer Command Prompt")
            print("Or install Build Tools for Visual Studio")
            return False

        # MSVC flags
        cmd.extend([
            "/LD",           # Build DLL
            "/EHsc",         # Exception handling
            "/std:c++17",    # C++17 standard
            "/O2",           # Optimization
            "/MD",           # Runtime library
        ])

        # Include directories
        for d in include_dirs:
            cmd.append(f'/I"{d}"')

        # Source files
        cmd.extend(str(s) for s in sources)

        # Output
        cmd.extend(["/Fe:", str(output_path)])

        # Link pybind11
        cmd.append("/link")
        cmd.append("python3.lib")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"MSVC compilation failed: {result.stderr[:500]}")
            return False
        else:
            print(f"✅ C++ extension built (MSVC): {output_path.name}")
            return True

    def _build_macos(self, sources, include_dirs, output_path):
        """Build using Clang on macOS."""
        cmd = ["c++", "-o", str(output_path)]
        cmd.extend(str(s) for s in sources)

        # Compiler flags
        cmd.extend(["-std=c++17", "-O3", "-fPIC"])

        # Include directories
        for d in include_dirs:
            cmd.append(f"-I{d}")

        # macOS specific
        cmd.extend(["-bundle", "-undefined", "dynamic_lookup"])

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Clang compilation failed: {result.stderr[:500]}")
            return False
        else:
            print(f"✅ C++ extension built (macOS): {output_path.name}")
            return True

    def _build_linux(self, sources, include_dirs, output_path):
        """Build using GCC/Clang on Linux."""
        cmd = ["c++", "-o", str(output_path)]
        cmd.extend(str(s) for s in sources)

        # Compiler flags
        cmd.extend(["-std=c++17", "-O3", "-fPIC"])

        # Include directories
        for d in include_dirs:
            cmd.append(f"-I{d}")

        # Linux shared library
        cmd.extend(["-shared"])

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"GCC compilation failed: {result.stderr[:500]}")
            return False
        else:
            print(f"✅ C++ extension built (Linux): {output_path.name}")
            return True


# Read README
readme = Path(__file__).parent / "README.md"
long_desc = readme.read_text() if readme.exists() else ""

setup(
    name="tls-fingerprint",
    version="1.0.0",
    description="Chromium-based TLS fingerprint library",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests*", "build*", "dist*"]),
    ext_modules=[Extension("tls_fingerprint._tls_fingerprint", sources=[])],
    cmdclass={"build_ext": BuildExt},
    package_data={"tls_fingerprint": ["*.py", "*.so", "*.pyd", "*.cc"]},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.8",
    install_requires=["pybind11>=2.10.0"],
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
