@echo off
REM Build BoringSSL for TLS Fingerprint Library
REM
REM Requirements:
REM   - CMake 3.22+
REM   - Visual Studio 2022 with C++ support
REM   - NASM (https://www.nasm.us/)
REM   - Ninja (optional, but recommended)
REM
REM Run this script from Visual Studio Developer Command Prompt or
REM run vcvars64.bat first:
REM   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

setlocal EnableDelayedExpansion

REM Get script directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo ========================================
echo   Building BoringSSL for Windows
echo ========================================
echo.

REM Check for required tools
where cmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: CMake not found. Please install CMake 3.22+
    exit /b 1
)

where nasm >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo WARNING: NASM not found. Some assembly optimizations will be disabled.
    echo Download from: https://www.nasm.us/
)

REM Check MSVC
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: MSVC compiler not found.
    echo Please run from Visual Studio Developer Command Prompt
    echo Or run: vcvars64.bat
    exit /b 1
)

REM Set paths
set BORINGSSL_DIR=%SCRIPT_DIR%third_party\boringssl
set BUILD_DIR=%SCRIPT_DIR%build\boringssl
set INSTALL_DIR=%BORINGSSL_DIR%\install

REM Check BoringSSL source
if not exist "%BORINGSSL_DIR%\CMakeLists.txt" (
    echo ERROR: BoringSSL source not found at %BORINGSSL_DIR%
    echo Please run: git submodule update --init --recursive
    exit /b 1
)

echo BoringSSL source: %BORINGSSL_DIR%
echo Build directory: %BUILD_DIR%
echo Install directory: %INSTALL_DIR%
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Configure CMake
echo Configuring BoringSSL with CMake...
cd /d "%BUILD_DIR%"

REM Try Ninja first, fallback to VS
where ninja >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Using Ninja generator...
    cmake "%BORINGSSL_DIR%" ^
        -GNinja ^
        -DCMAKE_BUILD_TYPE=Release ^
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON ^
        -DBUILD_SHARED_LIBS=OFF ^
        -DOPENSSL_SMALL=1
) else (
    echo Using Visual Studio generator...
    cmake "%BORINGSSL_DIR%" ^
        -G"Visual Studio 17 2022" ^
        -A x64 ^
        -DCMAKE_BUILD_TYPE=Release ^
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON ^
        -DBUILD_SHARED_LIBS=OFF ^
        -DOPENSSL_SMALL=1
)

if %ERRORLEVEL% neq 0 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo.
echo Building BoringSSL...

REM Build
where ninja >nul 2>&1
if %ERRORLEVEL% equ 0 (
    ninja
) else (
    cmake --build . --config Release --parallel
)

if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo Installing BoringSSL...

REM Create install directories
if not exist "%INSTALL_DIR%\lib" mkdir "%INSTALL_DIR%\lib"
if not exist "%INSTALL_DIR%\include" mkdir "%INSTALL_DIR%\include"

REM Copy libraries
if exist "ssl.lib" (
    copy /Y ssl.lib "%INSTALL_DIR%\lib\"
    copy /Y crypto.lib "%INSTALL_DIR%\lib\"
    echo Copied: ssl.lib, crypto.lib
) else if exist "Release\ssl.lib" (
    copy /Y Release\ssl.lib "%INSTALL_DIR%\lib\"
    copy /Y Release\crypto.lib "%INSTALL_DIR%\lib\"
    echo Copied: Release\ssl.lib, Release\crypto.lib
) else (
    echo ERROR: Could not find built libraries
    dir /s /b *.lib
    exit /b 1
)

REM Copy headers
xcopy /E /Y /Q "%BORINGSSL_DIR%\include\*" "%INSTALL_DIR%\include\"

echo.
echo ========================================
echo   BoringSSL Build Complete!
echo ========================================
echo.
echo Libraries: %INSTALL_DIR%\lib
dir "%INSTALL_DIR%\lib"
echo.
echo Headers: %INSTALL_DIR%\include
echo.
echo Next step: Build Python wheel
echo   cd python
echo   pip install pybind11
echo   python setup.py bdist_wheel
echo.

endlocal
