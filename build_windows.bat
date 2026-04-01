@echo off
REM TLS Fingerprint Library Build Script for Windows
REM
REM Usage: build_windows.bat [options]
REM
REM Options:
REM   --release       Build in release mode (default)
REM   --debug         Build in debug mode
REM   --clean         Clean build directory before building
REM   --test          Run tests after building
REM   --install       Install Python package after building
REM   --help          Show this help message

setlocal EnableDelayedExpansion

REM Default values
set BUILD_TYPE=Release
set CLEAN=0
set RUN_TESTS=0
set INSTALL=0
set BUILD_DIR=build

REM Parse arguments
:parse_args
if "%~1"=="" goto :done_args
if /I "%~1"=="--release" (
    set BUILD_TYPE=Release
    shift
    goto :parse_args
)
if /I "%~1"=="--debug" (
    set BUILD_TYPE=Debug
    shift
    goto :parse_args
)
if /I "%~1"=="--clean" (
    set CLEAN=1
    shift
    goto :parse_args
)
if /I "%~1"=="--test" (
    set RUN_TESTS=1
    shift
    goto :parse_args
)
if /I "%~1"=="--install" (
    set INSTALL=1
    shift
    goto :parse_args
)
if /I "%~1"=="--help" (
    echo TLS Fingerprint Library Build Script for Windows
    echo.
    echo Usage: %~nx0 [options]
    echo.
    echo Options:
    echo   --release       Build in release mode (default)
    echo   --debug         Build in debug mode
    echo   --clean         Clean build directory before building
    echo   --test          Run tests after building
    echo   --install       Install Python package after building
    echo   --help          Show this help message
    exit /b 0
)
echo Unknown option: %~1
exit /b 1

:done_args

REM Get script directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo ========================================
echo   TLS Fingerprint Library Build (Windows)
echo ========================================
echo.
echo Configuration:
echo   Build Type: %BUILD_TYPE%
echo   Build Dir:  %BUILD_DIR%
echo   Clean:      %CLEAN%
echo   Run Tests:  %RUN_TESTS%
echo   Install:    %INSTALL%
echo.

REM Clean if requested
if %CLEAN%==1 (
    echo Cleaning build directory...
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
    if exist "python\dist" rmdir /s /q "python\dist"
    if exist "python\build" rmdir /s /q "python\build"
    if exist "python\*.egg-info" del /q "python\*.egg-info"
    echo Clean complete.
    echo.
)

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Check for Visual Studio
where cl.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo WARNING: MSVC compiler (cl.exe) not found in PATH
    echo.
    echo Please run this script from one of:
    echo   - Visual Studio Developer Command Prompt
    echo   - x64 Native Tools Command Prompt for VS
    echo.
    echo Or run vcvars64.bat first:
    echo   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    echo.
    echo Falling back to pure Python implementation...
    set NO_MSVC=1
) else (
    set NO_MSVC=0
)

REM Step 1: Configure CMake (optional)
echo Step 1: Configuring CMake...
cd "%BUILD_DIR%"
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DBUILD_PYTHON_BINDINGS=ON -DBUILD_TESTS=OFF
if %ERRORLEVEL% neq 0 (
    echo CMake configuration failed, continuing with Python-only build
)
echo.

REM Step 2: Build Python wheel
echo Step 2: Building Python wheel package...
cd "%SCRIPT_DIR%python"

REM Clean previous builds
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"

REM Build wheel
python setup.py bdist_wheel
if %ERRORLEVEL% neq 0 (
    echo Failed to build wheel package
    exit /b 1
)

REM Check output
dir /b dist\*.whl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Wheel package not found
    exit /b 1
)

echo Wheel package created successfully
dir dist\*.whl
echo.

REM Step 3: Run tests if requested
if %RUN_TESTS%==1 (
    echo Step 3: Running tests...
    pip install --quiet pytest
    python -m pytest tests/ -v
    if %ERRORLEVEL% neq 0 (
        echo Tests failed
        exit /b 1
    )
    echo All tests passed.
    echo.
)

REM Step 4: Install if requested
if %INSTALL%==1 (
    echo Step 4: Installing Python package...
    cd "%SCRIPT_DIR%python"

    for %%f in (dist\*.whl) do pip install "%%f" --force-reinstall
    if %ERRORLEVEL% neq 0 (
        echo Failed to install Python package
        exit /b 1
    )

    echo Python package installed successfully.
    echo.

    REM Verify installation
    echo Verifying installation...
    python -c "import tls_fingerprint; print('tls_fingerprint imported successfully')"
    if %ERRORLEVEL% neq 0 (
        echo Verification failed
        exit /b 1
    )
    echo Verification successful.
)

REM Summary
echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo Output files:
echo   - Python wheel:   python\dist\tls_fingerprint-*.whl
echo.

if %INSTALL%==1 (
    echo The package is now installed and ready to use.
    echo.
    echo Quick start:
    echo   from tls_fingerprint import BrowserFingerprints, TLSHttpClient
    echo   config = BrowserFingerprints.chrome_desktop()
    echo   client = TLSHttpClient(config)
) else (
    echo To install the Python package:
    echo   pip install python\dist\tls_fingerprint-*.whl
)
echo.

endlocal
