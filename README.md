# TLS Fingerprint Library for Python

Chromium TLS 指纹功能提取库，用于模拟浏览器 TLS 指纹。

## 功能

- 提供浏览器 TLS 指纹配置（Chrome, Firefox, Safari, Edge）
- 生成 ClientHello 数据
- 自定义 TLS 指纹配置
- JSON/YAML 配置文件支持

## 文档

- **[使用说明 (USAGE.md)](docs/USAGE.md)** - 详细的 Python API 使用文档
- **[编译说明 (README.md#编译说明)](#编译说明)** - 构建和安装指南

---

## 编译说明

### 环境要求

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| Python | >= 3.8 | 运行环境和绑定生成 |
| CMake | >= 3.15 | 构建系统 |
| C++ 编译器 | GCC 9+ / Clang 10+ / MSVC 2019+ | 编译原生库 |
| pybind11 | >= 2.10 | Python C++ 绑定 |

### 平台支持

| 平台 | 编译器 | 状态 |
|------|--------|------|
| Linux | GCC / Clang | ✅ 支持 |
| macOS | Clang (Xcode) | ✅ 支持 |
| Windows | MSVC 2019+ | ✅ 支持 |

---

### 快速开始

#### 方式一：使用 Bash 脚本（Linux/macOS）

```bash
# 进入项目目录
cd tls_for_python

# 赋予执行权限
chmod +x build.sh

# 构建并安装
./build.sh --clean --install

# 带测试的完整构建
./build.sh --clean --test --install
```

#### 方式二：使用 Python 脚本（跨平台）

```bash
# 进入项目目录
cd tls_for_python

# 构建并安装
python build_python.py --clean --install

# 带测试的完整构建
python build_python.py --clean --test --install

# 仅构建 wheel 包
python build_python.py --clean
```

#### 方式三：手动构建

**步骤 1：安装 Python 依赖**

```bash
pip install pybind11 wheel build pytest
```

**步骤 2：配置 CMake**

```bash
# Linux/macOS
mkdir build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PYTHON_BINDINGS=ON \
    -DBUILD_TESTS=ON

# Windows (Visual Studio)
mkdir build && cd build
cmake .. \
    -G "Visual Studio 17 2022" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PYTHON_BINDINGS=ON \
    -DBUILD_TESTS=ON
```

**步骤 3：编译原生库**

```bash
# Linux/macOS
cmake --build . --config Release --parallel $(nproc)

# Windows
cmake --build . --config Release
```

**步骤 4：构建 Python Wheel**

```bash
cd ../python
python -m build --wheel --outdir dist/
```

**步骤 5：安装**

```bash
pip install dist/tls_fingerprint-1.0.0-*.whl
```

---

### 构建选项

#### Bash 脚本选项

| 选项 | 说明 |
|------|------|
| `--release` | Release 模式构建（默认） |
| `--debug` | Debug 模式构建 |
| `--clean` | 构建前清理构建目录 |
| `--test` | 构建完成后运行测试 |
| `--install` | 安装 Python 包到系统 |
| `--help` | 显示帮助信息 |

**示例：**

```bash
# Debug 构建
./build.sh --debug

# 完整构建流程
./build.sh --clean --test --install

# 仅构建不安装
./build.sh --clean --test
```

#### Python 脚本选项

| 选项 | 说明 |
|------|------|
| `--release` | Release 模式构建（默认） |
| `--debug` | Debug 模式构建 |
| `--clean` | 构建前清理构建目录 |
| `--test` | 构建完成后运行测试 |
| `--install` | 安装 Python 包到系统 |
| `-j, --jobs N` | 并行编译任务数 |

**示例：**

```bash
# 使用 8 个并行任务构建
python build_python.py --clean --install -j 8

# Debug 模式并运行测试
python build_python.py --debug --test
```

---

### 运行测试

```bash
# 方式一：通过构建脚本
./build.sh --test

# 方式二：直接运行 pytest
pip install pytest
pytest tests/python/ -v

# 方式三：运行 C++ 测试
cd build && ctest --output-on-failure
```

---

### 验证安装

```python
# 验证模块是否正确安装
python -c "from tls_fingerprint import BrowserFingerprints; print(BrowserFingerprints.chrome_desktop())"
```

---

### 常见问题

#### Q: 找不到 pybind11

```bash
pip install pybind11

# 或使用 conda
conda install pybind11
```

#### Q: CMake 版本过低

```bash
# Linux
pip install cmake --upgrade

# macOS
brew upgrade cmake

# Windows
# 从 https://cmake.org/download/ 下载最新版本
```

#### Q: 编译时找不到 BoringSSL

确保 `third_party/boringssl` 目录存在且包含完整的 BoringSSL 源码：

```bash
# 如果缺少 BoringSSL，请克隆
cd third_party
git clone https://boringssl.googlesource.com/boringssl
```

#### Q: macOS 编译错误

确保安装了 Xcode Command Line Tools：

```bash
xcode-select --install
```

#### Q: Windows 编译错误

1. 确保安装了 Visual Studio 2019 或更高版本
2. 确保在 "Desktop development with C++" 工作负载中
3. 使用 Visual Studio Developer Command Prompt

---

### 目录结构

```
tls_for_python/
├── build.sh              # Bash 构建脚本
├── build_python.py       # Python 构建脚本（跨平台）
├── CMakeLists.txt        # CMake 配置
├── README.md             # 本文档
│
├── include/              # C++ 头文件
│   └── tls_fingerprint/
│
├── src/                  # C++ 源文件（从 Chromium 提取）
│
├── python/               # Python 包
│   ├── tls_fingerprint/
│   │   ├── __init__.py
│   │   └── _bindings.cc  # pybind11 绑定
│   ├── setup.py
│   └── pyproject.toml
│
├── tests/                # 测试文件
│   ├── cpp/
│   └── python/
│
├── configs/              # 预定义配置文件
│
└── third_party/          # 第三方依赖
    └── boringssl/        # BoringSSL 加密库
```

---

### 从 PyPI 安装（未来支持）

```bash
pip install tls-fingerprint
```

---

## 使用示例

```python
from tls_fingerprint import (
    TLSFingerprintGenerator,
    BrowserFingerprints,
    ConfigLoader
)

# 使用预设的 Chrome 指纹
config = BrowserFingerprints.chrome_desktop()
generator = TLSFingerprintGenerator()
generator.set_config(config)

# 生成 ClientHello
client_hello = generator.generate_client_hello("example.com")
print(f"ClientHello length: {len(client_hello)} bytes")

# 自定义配置
config = BrowserFingerprints.chrome_desktop()
config.cipher_suites = [0x1301, 0x1302, 0x1303]  # TLS 1.3 only
generator.set_config(config)

# 从 JSON 文件加载配置
config = ConfigLoader.from_file("configs/chrome_120_desktop.json")
generator.set_config(config)
```

## 浏览器指纹

| 浏览器 | 方法 |
|--------|------|
| Chrome Desktop | `BrowserFingerprints.chrome_desktop()` |
| Chrome Android | `BrowserFingerprints.chrome_android()` |
| Firefox Desktop | `BrowserFingerprints.firefox_desktop()` |
| Safari | `BrowserFingerprints.safari()` |
| Edge | `BrowserFingerprints.edge()` |

## 依赖

- Python >= 3.8
- pybind11 >= 2.10
- BoringSSL (包含在 third_party 中)

## 许可证

BSD 3-Clause License

## 来源

本库从 Chromium 源代码提取 TLS 指纹配置功能。
原始代码版权归 The Chromium Authors 所有。
