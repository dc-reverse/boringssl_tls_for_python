# TLS Fingerprint Library

基于 Chromium BoringSSL 的 TLS 指纹库，用于模拟浏览器 TLS 握手指纹。

## 快速开始

### macOS M1/M2/M3/M4 (ARM64) - 预编译版本

```bash
# 1. 克隆项目
git clone https://github.com/dc-reverse/boringssl_tls_for_python.git
cd boringssl_tls_for_python

# 2. 安装 wheel（已包含预编译的 BoringSSL）
pip install python/dist/tls_fingerprint-1.0.0-cp312-cp312-macosx_10_13_universal2.whl

# 3. 测试
python -c "from tls_fingerprint import BrowserFingerprints; print(BrowserFingerprints.chrome_desktop())"
```

### macOS Intel / Windows / Linux

```bash
# 1. 克隆项目
git clone https://github.com/dc-reverse/boringssl_tls_for_python.git
cd boringssl_tls_for_python

# 2. 安装依赖
pip install pybind11 cmake ninja

# Windows 还需要安装:
# - Visual Studio 2022 (带 C++ 开发工具)
# - NASM (https://www.nasm.us/)

# 3. 编译 BoringSSL
./build_boringssl.sh          # macOS/Linux
build_boringssl.bat           # Windows (在 VS Developer Command Prompt 中运行)

# 4. 构建 Python wheel
cd python
python setup.py bdist_wheel

# 5. 安装
pip install dist/*.whl
```

## 使用示例

```python
from tls_fingerprint import BrowserFingerprints, TLSHttpClient

# 获取 Chrome 浏览器指纹
config = BrowserFingerprints.chrome_desktop()

# 创建 HTTP 客户端（支持代理）
client = TLSHttpClient(config, proxy="http://127.0.0.1:7897")

# 发送请求
response = client.get("https://example.com")
print(response.text)

# 支持的浏览器指纹
firefox = BrowserFingerprints.firefox_desktop()
safari = BrowserFingerprints.safari()
edge = BrowserFingerprints.edge()
```

## 目录结构

```
boringssl_tls_for_python/
├── python/                      # Python 包
│   ├── src/                     # C++ 源码
│   ├── tls_fingerprint/         # Python 模块
│   ├── include/                 # C++ 头文件
│   └── dist/                    # 预编译 wheel
├── third_party/
│   └── boringssl/               # BoringSSL 源码和预编译库
│       ├── install/             # 预编译的 BoringSSL
│       │   ├── lib/             # libssl.a, libcrypto.a
│       │   └── include/         # OpenSSL 头文件
│       └── ...                  # BoringSSL 源码
├── build_boringssl.sh           # macOS/Linux 编译脚本
└── build_boringssl.bat          # Windows 编译脚本
```

## 依赖要求

### 运行时
- Python 3.8+
- requests

### 编译时
- CMake 3.22+
- C++17 编译器 (GCC 6.1+, Clang, 或 MSVC 2022+)
- pybind11
- Ninja (推荐)

### Windows 额外依赖
- Visual Studio 2022 with C++ workload
- NASM (https://www.nasm.us/)

## API 文档

### BrowserFingerprints

```python
# 获取预定义的浏览器指纹配置
config = BrowserFingerprints.chrome_desktop()    # Chrome 桌面版
config = BrowserFingerprints.chrome_android()    # Chrome Android
config = BrowserFingerprints.firefox_desktop()   # Firefox 桌面版
config = BrowserFingerprints.safari()            # Safari
config = BrowserFingerprints.edge()              # Edge

# 配置属性
config.cipher_suites        # 密码套件列表
config.signature_algorithms # 签名算法列表
config.named_groups         # 椭圆曲线列表
config.alpn_protocols       # ALPN 协议列表
config.enable_grease        # 是否启用 GREASE
```

### TLSHttpClient

```python
# 创建客户端
client = TLSHttpClient(config)

# 带代理
client = TLSHttpClient(config, proxy="http://127.0.0.1:7897")
client = TLSHttpClient(config, proxy="socks5://127.0.0.1:1080")

# 发送请求
response = client.get("https://example.com")
response = client.post("https://api.example.com", json={"key": "value"})

# 响应对象
response.text       # 响应文本
response.json()     # JSON 解析
response.status_code # 状态码
response.headers    # 响应头
```

### TLSFingerprintGenerator

```python
from tls_fingerprint import TLSFingerprintGenerator, BrowserFingerprints

# 创建生成器
generator = TLSFingerprintGenerator()
generator.set_config(BrowserFingerprints.chrome_desktop())

# 生成 ClientHello
client_hello = generator.generate_client_hello("example.com")
print(f"ClientHello bytes: {len(client_hello)}")
```

## 许可证

BSD 3-Clause License
