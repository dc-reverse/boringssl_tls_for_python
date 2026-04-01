"""
Setup script for TLS Fingerprint Library
Source distribution that compiles C++ during pip install
"""

import os
import sys
import subprocess
from pathlib import Path
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext as _build_ext


class BuildExt(_build_ext):
    """Build C++ extension."""

    def run(self):
        for ext in self.extensions:
            self._build_extension(ext)

    def _build_extension(self, ext):
        project_root = Path(__file__).parent

        # Source files
        sources = [
            project_root / "src" / "tls_fingerprint_config.cc",
            project_root / "src" / "tls_fingerprint_generator.cc",
            project_root / "python" / "tls_fingerprint" / "_bindings.cc",
        ]

        # Check sources exist
        missing = [s for s in sources if not s.exists()]
        if missing:
            print(f"C++ sources not found, using pure Python: {missing}")
            return

        # Include directories
        include_dirs = [project_root / "include"]

        # Try pybind11
        try:
            import pybind11
            include_dirs.append(Path(pybind11.get_include()))
        except ImportError:
            print("pybind11 not found, install with: pip install pybind11")
            return

        # Add Python include
        import sysconfig
        py_inc = sysconfig.get_path('include')
        if py_inc:
            include_dirs.append(Path(py_inc))

        include_dirs = [d for d in include_dirs if d.exists()]

        # Compiler flags
        cxxflags = ["-std=c++17", "-O3", "-fPIC"]
        for d in include_dirs:
            cxxflags.append(f"-I{d}")

        # Output
        ext_filename = self.get_ext_filename(ext.name)
        output_path = Path(self.build_lib) / "tls_fingerprint" / ext_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"Building C++ extension for Python {sys.version_info.major}.{sys.version_info.minor}...")

        # Build command
        cmd = ["c++", "-o", str(output_path)]
        cmd.extend(str(s) for s in sources)
        cmd.extend(cxxflags)

        if sys.platform == "darwin":
            cmd.extend(["-bundle", "-undefined", "dynamic_lookup"])
        elif sys.platform == "linux":
            cmd.extend(["-shared"])

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"C++ compilation failed: {result.stderr[:500]}")
            print("Using pure Python implementation")
        else:
            print(f"✅ C++ extension built: {output_path.name}")


# Read README
readme = Path(__file__).parent / "python" / "README.md"
long_desc = readme.read_text() if readme.exists() else ""

setup(
    name="tls-fingerprint",
    version="1.0.0",
    description="Chromium-based TLS fingerprint library",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    package_dir={"": "python"},
    packages=find_packages(where="python", exclude=["tests*"]),
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
