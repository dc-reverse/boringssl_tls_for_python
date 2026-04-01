# TLS Fingerprint Library - Python 使用说明

本文档详细介绍如何在 Python 中使用 TLS 指纹库来模拟浏览器 TLS 指纹。

---

## 目录

- [安装](#安装)
- [可用功能](#可用功能)
- [快速开始](#快速开始)
- [API 参考](#api-参考)
- [浏览器指纹预设](#浏览器指纹预设)
- [自定义指纹配置](#自定义指纹配置)
- [高级用法](#高级用法)
- [完整示例](#完整示例)
- [常见问题](#常见问题)

---

## 安装

### 方式一：从 Wheel 文件安装（推荐）

**Step 1: 构建 Wheel 包**

```bash
cd tls_for_python

# 完整构建（包含编译和打包）
./build.sh --clean

# 生成的 wheel 文件位于：
# python/dist/tls_fingerprint-1.0.0-py3-none-any.whl
```

**Step 2: 安装 Wheel**

```bash
# 安装到当前 Python 环境
pip3 install python/dist/tls_fingerprint-1.0.0-py3-none-any.whl

# 或者安装到用户目录
pip3 install --user python/dist/tls_fingerprint-1.0.0-py3-none-any.whl
```

**Step 3: 验证安装**

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator
print("✅ 安装成功!")

config = BrowserFingerprints.chrome_desktop()
generator = TLSFingerprintGenerator()
generator.set_config(config)
client_hello = generator.generate_client_hello("example.com")
print(f"ClientHello: {len(client_hello)} bytes")
```

### 方式二：分发到其他机器

将 wheel 文件复制到目标机器，然后安装：

```bash
# 在目标机器上执行
pip3 install tls_fingerprint-1.0.0-py3-none-any.whl
```

**注意**: Wheel 文件是跨平台通用的 pure Python 包格式，但包含的 `.so` 文件是平台特定的。

当前编译的 wheel 仅支持：
- macOS (arm64/x86_64)
- Python 3.8+

### 方式三：从源码编译安装

```bash
cd tls_for_python
./build.sh --clean --install
```

### 卸载

```bash
pip3 uninstall tls-fingerprint
```

### 更新安装

```bash
# 重新构建并安装
cd tls_for_python
./build.sh --clean
pip3 uninstall tls-fingerprint -y
pip3 install python/dist/tls_fingerprint-1.0.0-py3-none-any.whl
```

---

## Wheel 包说明

### 包内容

```
tls_fingerprint-1.0.0-py3-none-any.whl
├── tls_fingerprint/
│   ├── __init__.py                        # Python 包入口
│   └── _tls_fingerprint.cpython-312-*.so  # 编译的扩展模块
└── tls_fingerprint-1.0.0.dist-info/       # 包元数据
```

### 文件大小

约 **133KB**，非常轻量。

### 分发方式

| 方式 | 命令 |
|------|------|
| 本地安装 | `pip install tls_fingerprint-1.0.0-py3-none-any.whl` |
| 从 HTTP 服务器 | `pip install http://example.com/tls_fingerprint-1.0.0-py3-none-any.whl` |
| 从文件服务器 | `pip install /path/to/tls_fingerprint-1.0.0-py3-none-any.whl` |
| requirements.txt | `/path/to/tls_fingerprint-1.0.0-py3-none-any.whl` |

---

## 在 requirements.txt 中使用

```txt
# 方式一：使用本地路径
/path/to/tls_fingerprint-1.0.0-py3-none-any.whl

# 方式二：使用 HTTP URL
http://your-server.com/packages/tls_fingerprint-1.0.0-py3-none-any.whl
```

然后：

```bash
pip3 install -r requirements.txt
```

---

## 手动安装到其他项目（备选方案）

编译完成后，可以通过以下方式将库安装到其他项目中：

#### 方式一：复制模块目录

```bash
# 编译后，将 python/tls_fingerprint 目录复制到目标项目
cp -r tls_for_python/python/tls_fingerprint /path/to/your_project/

# 然后在代码中直接导入
cd /path/to/your_project
python3 -c "from tls_fingerprint import BrowserFingerprints; print(BrowserFingerprints.chrome_desktop())"
```

#### 方式二：添加到 PYTHONPATH

```bash
# 将 python 目录添加到 PYTHONPATH
export PYTHONPATH="/path/to/tls_for_python/python:$PYTHONPATH"

# 然后在任意位置导入使用
python3 -c "from tls_fingerprint import BrowserFingerprints; print('OK')"
```

#### 方式三：使用 sys.path 动态添加

```python
import sys
sys.path.insert(0, '/path/to/tls_for_python/python')

from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

config = BrowserFingerprints.chrome_desktop()
generator = TLSFingerprintGenerator()
generator.set_config(config)
```

#### 方式四：安装到 site-packages（推荐）

```bash
# 手动复制到 Python site-packages
PYTHON_SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")
cp -r tls_for_python/python/tls_fingerprint "$PYTHON_SITE_PACKAGES/"

# 验证安装
python3 -c "import tls_fingerprint; print(tls_fingerprint.__version__)"
```

#### 方式五：打包为 wheel 文件

```bash
# 如果网络可用，可以打包为 wheel
cd tls_for_python/python
pip3 wheel . --no-deps -w dist/

# 然后在其他机器上安装
pip3 install dist/tls_fingerprint-1.0.0-*.whl
```

#### 目录结构说明

编译完成后，需要的文件：

```
tls_for_python/python/tls_fingerprint/
├── __init__.py                      # Python 包初始化
├── _tls_fingerprint.cpython-312-*.so  # 编译的扩展模块
└── utils.py                         # 工具函数（可选）
```

只需将整个 `tls_fingerprint` 目录复制到目标位置即可。

---

## 可用功能

### 高级 API（推荐）

| 类/函数 | 说明 |
|------|------|
| `TLSSession` | TLS 会话类，创建对象时自动分配指纹，同一会话保持相同指纹 |
| `TLSClient` | 多会话管理器，管理多个独立的 TLS 会话 |
| `TLSFingerprintPool` | 预生成指纹池，高性能场景使用 |
| `create_session(browser_type)` | 快速创建会话 |
| `create_random_session()` | 快速创建随机指纹会话 |
| `generate_client_hello(host, browser_type)` | 快速生成 ClientHello |

### HTTP 客户端（支持代理）

| 类/函数 | 说明 |
|------|------|
| `TLSHttpClient` | HTTP 客户端，支持自定义 TLS 指纹和代理 |
| `ProxyConfig` | 代理配置类（HTTP/HTTPS/SOCKS5） |
| `HttpResponse` | HTTP 响应对象 |
| `http_get(url, browser_type, proxy)` | 快速 GET 请求 |
| `http_post(url, browser_type, proxy, body)` | 快速 POST 请求 |

### 核心类

| 类 | 说明 |
|------|------|
| `TLSFingerprintConfig` | TLS 指纹配置类 |
| `TLSFingerprintGenerator` | ClientHello 生成器 |
| `TLSFingerprintAnalyzer` | TLS 指纹分析器 |
| `BrowserFingerprints` | 浏览器指纹预设工厂 |

### 浏览器指纹预设

| 方法 | 说明 |
|------|------|
| `BrowserFingerprints.chrome_desktop()` | Chrome 桌面版指纹 |
| `BrowserFingerprints.chrome_android()` | Chrome Android 指纹 |
| `BrowserFingerprints.firefox_desktop()` | Firefox 桌面版指纹 |
| `BrowserFingerprints.safari()` | Safari 指纹 |
| `BrowserFingerprints.edge()` | Edge 指纹（与 Chrome 相同） |

### 工具函数

| 函数 | 说明 |
|------|------|
| `get_cipher_suite_name(cipher_suite)` | 获取密码套件可读名称 |
| `get_cipher_suite_version(cipher_suite)` | 获取密码套件 TLS 版本 |
| `get_signature_algorithm_name(sig_alg)` | 获取签名算法可读名称 |
| `get_named_group_name(named_group)` | 获取命名组可读名称 |

### 常量

#### 密码套件常量

```python
from tls_fingerprint import (
    TLS_AES_128_GCM_SHA256,           # 0x1301
    TLS_AES_256_GCM_SHA384,           # 0x1302
    TLS_CHACHA20_POLY1305_SHA256,     # 0x1303
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  # 0xC02B
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    # 0xC02F
)
```

#### 签名算法常量

```python
from tls_fingerprint import (
    ECDSA_SECP256R1_SHA256,  # 0x0403
    RSA_PSS_RSAE_SHA256,     # 0x0804
    RSA_PKCS1_SHA256,        # 0x0401
)
```

#### 命名组常量

```python
from tls_fingerprint import (
    X25519,      # 0x001D
    SECP256R1,   # 0x0017
    SECP384R1,   # 0x0018
)
```

---

## 快速开始

### 推荐：使用高级 API（TLSSession）

```python
from tls_fingerprint import TLSSession, TLSClient

# 方式1: 创建随机指纹会话（推荐）
session = TLSSession(browser_type="random")

# 方式2: 创建指定浏览器指纹会话
session = TLSSession(browser_type="chrome")  # chrome, firefox, safari, edge

# 生成 ClientHello（同一会话使用相同指纹）
client_hello = session.generate_client_hello("example.com")
print(f"Session ID: {session.session_id}")
print(f"Browser: {session.browser_type}")
print(f"ClientHello: {len(client_hello)} bytes")
```

### 基本使用（底层 API）

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

# 1. 获取 Chrome 浏览器指纹配置
config = BrowserFingerprints.chrome_desktop()

# 2. 创建生成器并设置配置
generator = TLSFingerprintGenerator()
generator.set_config(config)

# 3. 生成 ClientHello 数据
client_hello = generator.generate_client_hello("example.com")

print(f"ClientHello 大小: {len(client_hello)} 字节")
print(f"ClientHello 数据: {client_hello[:32].hex()}...")
```

---

## 高级 API

### TLSSession - TLS 会话类

创建一个会话，自动管理 TLS 指纹。**同一会话的所有请求使用相同的 TLS 指纹。**

```python
from tls_fingerprint import TLSSession

# 创建随机浏览器指纹会话
session = TLSSession(browser_type="random")

# 可用浏览器类型:
# - "chrome" / "chrome_desktop"  - Chrome 桌面版
# - "chrome_android"             - Chrome Android
# - "firefox" / "firefox_desktop" - Firefox 桌面版
# - "safari"                     - Safari
# - "edge"                       - Edge
# - "random"                     - 随机选择一个浏览器

# 获取会话信息
print(f"Session ID: {session.session_id}")       # 唯一会话ID
print(f"Browser: {session.browser_type}")        # 浏览器类型
print(f"JA3 Hash: {session.get_ja3_hash()}")     # JA3 指纹哈希

# 生成 ClientHello
client_hello = session.generate_client_hello("example.com")
hex_hello = session.get_client_hello_hex("example.com")  # 十六进制格式

# 导出会话信息
info = session.to_dict()
# {'session_id': '...', 'browser_type': 'chrome', 'created_at': ..., 'ja3_hash': '...'}
```

### TLSClient - 多会话管理

管理多个 TLS 会话，适合需要不同指纹的场景。

```python
from tls_fingerprint import TLSClient

# 创建客户端
client = TLSClient(default_browser="chrome")

# 创建多个会话
session1 = client.create_session("chrome")
session2 = client.create_session("firefox")
session3 = client.create_session("random")

# 获取会话
session = client.get_session(session1.session_id)

# 列出所有会话
for info in client.list_sessions():
    print(f"Session: {info['session_id']}, Browser: {info['browser_type']}")

# 移除会话
client.remove_session(session1.session_id)

# 清空所有会话
client.clear_sessions()

# 获取会话数量
print(f"Active sessions: {client.session_count}")
```

### TLSFingerprintPool - 指纹池

预生成多个指纹，适合高性能场景。

```python
from tls_fingerprint import TLSFingerprintPool

# 创建指纹池（预生成 10 个随机指纹）
pool = TLSFingerprintPool(pool_size=10)

# 可选: 指定浏览器类型
pool = TLSFingerprintPool(
    pool_size=20,
    browser_types=["chrome", "firefox", "safari"]
)

# 随机获取一个指纹
session = pool.get_random()

# 轮询获取指纹（round-robin）
session = pool.get_next()

# 刷新池（重新生成）
pool.refresh()

# 获取池大小
print(f"Pool size: {len(pool)}")
```

### 便捷函数

```python
from tls_fingerprint import create_session, create_random_session, generate_client_hello

# 快速创建会话
session = create_session("chrome")

# 快速创建随机会话
session = create_random_session()

# 快速生成 ClientHello（一次性使用）
data = generate_client_hello("example.com", browser_type="chrome")
```

### 完整示例：多请求保持相同指纹

```python
from tls_fingerprint import TLSSession

# 创建会话（自动分配指纹）
session = TLSSession(browser_type="random")

print(f"Using browser: {session.browser_type}")
print(f"Session ID: {session.session_id}")

# 同一会话的多次请求使用相同指纹
hosts = ["api.example.com", "www.example.com", "cdn.example.com"]

for host in hosts:
    client_hello = session.generate_client_hello(host)
    print(f"{host}: {len(client_hello)} bytes, fingerprint: {session.get_ja3_hash()[:8]}...")
```

### 完整示例：多账户多指纹

```python
from tls_fingerprint import TLSClient

# 创建客户端
client = TLSClient()

# 为每个账户创建独立的会话（不同指纹）
accounts = ["user1", "user2", "user3"]
sessions = {}

for account in accounts:
    session = client.create_session("random")
    sessions[account] = session
    print(f"{account}: session={session.session_id}, browser={session.browser_type}")

# 使用时获取对应账户的会话
def make_request(account, url):
    session = sessions[account]
    # 使用 session 进行请求...
    client_hello = session.generate_client_hello(url)
    return client_hello

# 每个账户始终使用相同的 TLS 指纹
make_request("user1", "api.example.com")
make_request("user2", "api.example.com")
```

---

## HTTP 客户端（支持代理）

### TLSHttpClient - HTTP 客户端

支持自定义 TLS 指纹和代理的 HTTP 客户端。

```python
from tls_fingerprint import TLSHttpClient

# 创建客户端
client = TLSHttpClient(browser_type="chrome")

# 发送请求
response = client.get("https://httpbin.org/ip")
print(f"Status: {response.status_code}")
print(f"Body: {response.text}")
```

### 代理支持

支持 HTTP/HTTPS/SOCKS5 代理：

```python
from tls_fingerprint import TLSHttpClient

# HTTP 代理
client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://127.0.0.1:8080"
)

# 带认证的代理
client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://user:password@proxy.example.com:8080"
)

# SOCKS5 代理
client = TLSHttpClient(
    browser_type="random",
    proxy="socks5://127.0.0.1:1080"
)

# 发送请求
response = client.get("https://example.com")
print(response.text)
```

### 动态切换代理

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

# 设置代理
client.set_proxy("http://127.0.0.1:8080")
response1 = client.get("https://httpbin.org/ip")

# 切换代理
client.set_proxy("socks5://127.0.0.1:1080")
response2 = client.get("https://httpbin.org/ip")

# 清除代理（直连）
client.clear_proxy()
response3 = client.get("https://httpbin.org/ip")
```

### POST 请求

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome", proxy="http://127.0.0.1:8080")

# JSON 数据
import json
response = client.post(
    "https://httpbin.org/post",
    headers={"Content-Type": "application/json"},
    body=json.dumps({"key": "value"}).encode()
)
print(response.json())

# 表单数据
response = client.post(
    "https://httpbin.org/post",
    body={"username": "test", "password": "123456"}
)
print(response.json())
```

### 保持会话一致性

```python
from tls_fingerprint import TLSHttpClient, TLSSession

# 创建会话
session = TLSSession(browser_type="random")

# 使用相同会话创建客户端（保持相同指纹）
client = TLSHttpClient(session=session)

# 所有请求使用相同的 TLS 指纹
r1 = client.get("https://httpbin.org/ip")
r2 = client.get("https://httpbin.org/headers")

print(f"Session: {session.session_id}")
print(f"Browser: {session.browser_type}")
```

### ProxyConfig - 代理配置

```python
from tls_fingerprint import ProxyConfig

# 从 URL 创建
proxy = ProxyConfig.from_url("http://user:pass@127.0.0.1:8080")
print(proxy.host)        # 127.0.0.1
print(proxy.port)        # 8080
print(proxy.username)    # user
print(proxy.password)    # pass
print(proxy.proxy_type)  # http

# 手动创建
proxy = ProxyConfig(
    host="127.0.0.1",
    port=1080,
    proxy_type="socks5",
    username="user",
    password="pass"
)
```

### HttpResponse - 响应对象

```python
response = client.get("https://httpbin.org/get")

# 状态码
print(response.status_code)  # 200

# 响应头
print(response.headers)      # {'content-type': 'application/json', ...}

# 响应体（字节）
print(response.body)         # b'{"args":{}...}'

# 响应体（文本）
print(response.text)         # '{"args":{}...}'

# 解析 JSON
data = response.json()
print(data)                  # {'args': {}, ...}

# HTTP 版本
print(response.http_version) # HTTP/1.1
```

### 便捷函数

```python
from tls_fingerprint import http_get, http_post

# 快速 GET 请求
response = http_get(
    "https://httpbin.org/ip",
    browser_type="chrome",
    proxy="http://127.0.0.1:8080"
)
print(response.text)

# 快速 POST 请求
response = http_post(
    "https://httpbin.org/post",
    browser_type="firefox",
    body={"key": "value"}
)
print(response.json())
```

### 完整示例：爬虫

```python
from tls_fingerprint import TLSHttpClient

# 创建客户端（模拟 Chrome，使用代理）
client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://127.0.0.1:7890",
    timeout=10.0,
    default_headers={
        "Referer": "https://www.google.com/",
    }
)

# 请求列表
urls = [
    "https://httpbin.org/ip",
    "https://httpbin.org/headers",
    "https://httpbin.org/user-agent",
]

for url in urls:
    try:
        response = client.get(url)
        print(f"{url}: {response.status_code} ({len(response.body)} bytes)")
    except Exception as e:
        print(f"{url}: Error - {e}")
```

---

## API 参考

### TLSFingerprintConfig

TLS 指纹配置类，包含所有 TLS 握手相关的配置参数。

#### 属性

| 属性 | 类型 | 说明 |
|------|------|------|
| `version_min` | `int` | 最小 TLS 版本 (0x0303=TLS1.2, 0x0304=TLS1.3) |
| `version_max` | `int` | 最大 TLS 版本 |
| `cipher_suites` | `List[int]` | 密码套件列表（按优先级排序） |
| `signature_algorithms` | `List[int]` | 签名算法列表 |
| `named_groups` | `List[int]` | 命名组/椭圆曲线列表 |
| `alpn_protocols` | `List[str]` | ALPN 协议列表 |
| `permute_extensions` | `bool` | 是否随机排列扩展顺序 |
| `enable_grease` | `bool` | 是否启用 GREASE 扩展 |

#### 示例

```python
from tls_fingerprint import TLSFingerprintConfig

# 创建自定义配置
config = TLSFingerprintConfig()
config.version_min = 0x0303  # TLS 1.2
config.version_max = 0x0304  # TLS 1.3
config.cipher_suites = [0x1301, 0x1302, 0x1303]
config.signature_algorithms = [0x0403, 0x0804]
config.named_groups = [0x001D, 0x0017]
config.alpn_protocols = ["h2", "http/1.1"]
config.permute_extensions = True
config.enable_grease = True
```

---

### TLSFingerprintGenerator

TLS 指纹生成器，用于生成 ClientHello 数据。

#### 方法

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `set_config(config)` | `TLSFingerprintConfig` | `None` | 设置指纹配置 |
| `get_config()` | - | `TLSFingerprintConfig` | 获取当前配置 |
| `generate_client_hello(hostname)` | `str` | `bytes` | 生成 ClientHello 数据 |

#### 示例

```python
from tls_fingerprint import TLSFingerprintGenerator, BrowserFingerprints

# 创建生成器
generator = TLSFingerprintGenerator()

# 设置 Chrome 指纹
config = BrowserFingerprints.chrome_desktop()
generator.set_config(config)

# 为指定主机名生成 ClientHello
client_hello = generator.generate_client_hello("www.google.com")

# 输出信息
print(f"生成的 ClientHello 大小: {len(client_hello)} 字节")
```

---

### BrowserFingerprints

浏览器指纹预设工厂类，提供常见浏览器的 TLS 指纹配置。

#### 静态方法

| 方法 | 说明 |
|------|------|
| `chrome_desktop()` | Chrome 桌面版指纹 |
| `chrome_android()` | Chrome Android 指纹 |
| `firefox_desktop()` | Firefox 桌面版指纹 |
| `safari()` | Safari 指纹 |
| `edge()` | Edge 指纹（与 Chrome 相同） |

#### 示例

```python
from tls_fingerprint import BrowserFingerprints

# 获取各种浏览器指纹
chrome = BrowserFingerprints.chrome_desktop()
firefox = BrowserFingerprints.firefox_desktop()
safari = BrowserFingerprints.safari()
edge = BrowserFingerprints.edge()

# 比较密码套件数量
print(f"Chrome 密码套件: {len(chrome.cipher_suites)}")
print(f"Firefox 密码套件: {len(firefox.cipher_suites)}")
print(f"Safari 密码套件: {len(safari.cipher_suites)}")
```

---

### TLSFingerprintAnalyzer

TLS 指纹分析器，用于识别浏览器类型。

#### 静态方法

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `identify_browser(config)` | `TLSFingerprintConfig` | `str` | 根据配置识别浏览器类型 |

#### 示例

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintAnalyzer

# 获取 Chrome 指纹
config = BrowserFingerprints.chrome_desktop()

# 识别浏览器
browser = TLSFingerprintAnalyzer.identify_browser(config)
print(f"识别结果: {browser}")  # 输出: Chrome
```

---

### 工具函数

#### get_cipher_suite_name(cipher_suite: int) -> str

获取密码套件的可读名称。

```python
from tls_fingerprint import get_cipher_suite_name, TLS_AES_128_GCM_SHA256

name = get_cipher_suite_name(TLS_AES_128_GCM_SHA256)
print(name)  # 输出: TLS_AES_128_GCM_SHA256
```

#### get_cipher_suite_version(cipher_suite: int) -> str

获取密码套件对应的 TLS 版本。

```python
from tls_fingerprint import get_cipher_suite_version, TLS_AES_128_GCM_SHA256

version = get_cipher_suite_version(TLS_AES_128_GCM_SHA256)
print(version)  # 输出: TLS 1.3
```

#### get_signature_algorithm_name(sig_alg: int) -> str

获取签名算法的可读名称。

```python
from tls_fingerprint import get_signature_algorithm_name, ECDSA_SECP256R1_SHA256

name = get_signature_algorithm_name(ECDSA_SECP256R1_SHA256)
print(name)  # 输出: ECDSA_SECP256R1_SHA256
```

#### get_named_group_name(named_group: int) -> str

获取命名组的可读名称。

```python
from tls_fingerprint import get_named_group_name, X25519

name = get_named_group_name(X25519)
print(name)  # 输出: x25519
```

---

## 浏览器指纹预设

### Chrome 桌面版

```python
config = BrowserFingerprints.chrome_desktop()
```

特点：
- 支持 TLS 1.2 和 TLS 1.3
- 9 个密码套件
- 8 个签名算法
- 3 个命名组 (x25519, secp256r1, secp384r1)
- 启用 GREASE 扩展
- 启用扩展随机排列
- ALPN: h2, http/1.1

### Firefox 桌面版

```python
config = BrowserFingerprints.firefox_desktop()
```

特点：
- 支持 TLS 1.2 和 TLS 1.3
- 9 个密码套件
- 7 个签名算法
- 不使用 GREASE
- 不随机排列扩展

### Safari

```python
config = BrowserFingerprints.safari()
```

特点：
- 支持 TLS 1.2 和 TLS 1.3
- 6 个密码套件
- 9 个签名算法
- 4 个命名组（支持 secp521r1）
- 不使用 GREASE

---

## 自定义指纹配置

### 创建自定义配置

```python
from tls_fingerprint import TLSFingerprintConfig, TLSFingerprintGenerator

# 创建自定义配置
config = TLSFingerprintConfig()

# 设置 TLS 版本范围
config.version_min = 0x0303  # TLS 1.2
config.version_max = 0x0304  # TLS 1.3

# 设置密码套件（TLS 1.3）
config.cipher_suites = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
]

# 设置签名算法
config.signature_algorithms = [
    0x0403,  # ECDSA_SECP256R1_SHA256
    0x0804,  # RSA_PSS_RSAE_SHA256
    0x0401,  # RSA_PKCS1_SHA256
]

# 设置命名组
config.named_groups = [
    0x001D,  # x25519
    0x0017,  # secp256r1
]

# 设置 ALPN 协议
config.alpn_protocols = ["h2", "http/1.1"]

# 高级设置
config.permute_extensions = True  # 随机排列扩展
config.enable_grease = False      # 禁用 GREASE

# 使用自定义配置
generator = TLSFingerprintGenerator()
generator.set_config(config)
client_hello = generator.generate_client_hello("example.com")
```

### 修改预设配置

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

# 从 Chrome 预设开始
config = BrowserFingerprints.chrome_desktop()

# 只修改密码套件（仅使用 TLS 1.3）
config.cipher_suites = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
]

# 禁用 GREASE 使其更像普通客户端
config.enable_grease = False

# 使用修改后的配置
generator = TLSFingerprintGenerator()
generator.set_config(config)
```

---

## 高级用法

### 比较不同浏览器指纹

```python
from tls_fingerprint import BrowserFingerprints

browsers = {
    "Chrome": BrowserFingerprints.chrome_desktop(),
    "Firefox": BrowserFingerprints.firefox_desktop(),
    "Safari": BrowserFingerprints.safari(),
    "Edge": BrowserFingerprints.edge(),
}

print("浏览器指纹比较:")
print("-" * 60)
print(f"{'浏览器':<12} {'密码套件':>10} {'签名算法':>10} {'命名组':>10}")
print("-" * 60)

for name, config in browsers.items():
    print(f"{name:<12} {len(config.cipher_suites):>10} "
          f"{len(config.signature_algorithms):>10} "
          f"{len(config.named_groups):>10}")
```

输出：
```
浏览器指纹比较:
------------------------------------------------------------
浏览器         密码套件     签名算法      命名组
------------------------------------------------------------
Chrome               9          8          3
Firefox              9          7          3
Safari               6          9          4
Edge                 9          8          3
```

### 批量生成 ClientHello

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

# 配置生成器
config = BrowserFingerprints.chrome_desktop()
generator = TLSFingerprintGenerator()
generator.set_config(config)

# 批量生成
hosts = ["google.com", "github.com", "stackoverflow.com", "reddit.com"]

for host in hosts:
    client_hello = generator.generate_client_hello(host)
    print(f"{host}: {len(client_hello)} bytes")
```

### 与 requests 库集成

```python
import requests
from tls_fingerprint import BrowserFingerprints

# 获取 Chrome 指纹配置
config = BrowserFingerprints.chrome_desktop()

# 打印指纹信息（用于调试）
print("使用 Chrome 指纹:")
print(f"  密码套件数量: {len(config.cipher_suites)}")
print(f"  ALPN 协议: {config.alpn_protocols}")

# 注意：实际 TLS 指纹应用需要配合底层 SSL 库
# 这里仅演示配置获取
```

---

## 完整示例

### 示例 1: 生成并分析 ClientHello

```python
from tls_fingerprint import (
    BrowserFingerprints,
    TLSFingerprintGenerator,
    TLSFingerprintAnalyzer,
    get_cipher_suite_name,
)

# 生成 ClientHello
config = BrowserFingerprints.chrome_desktop()
generator = TLSFingerprintGenerator()
generator.set_config(config)

hostname = "www.example.com"
client_hello = generator.generate_client_hello(hostname)

print(f"ClientHello 生成完成")
print(f"  目标主机: {hostname}")
print(f"  数据大小: {len(client_hello)} 字节")
print(f"  前 32 字节: {client_hello[:32].hex()}")

# 识别浏览器
browser = TLSFingerprintAnalyzer.identify_browser(config)
print(f"  浏览器识别: {browser}")

# 打印密码套件
print(f"\n密码套件列表:")
for i, cs in enumerate(config.cipher_suites, 1):
    name = get_cipher_suite_name(cs)
    print(f"  {i}. {name} (0x{cs:04X})")
```

### 示例 2: 多浏览器轮换

```python
import random
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

# 获取所有浏览器指纹
fingerprints = [
    ("Chrome", BrowserFingerprints.chrome_desktop()),
    ("Firefox", BrowserFingerprints.firefox_desktop()),
    ("Safari", BrowserFingerprints.safari()),
    ("Edge", BrowserFingerprints.edge()),
]

generator = TLSFingerprintGenerator()

# 模拟随机轮换浏览器指纹
hosts = ["api.example.com", "www.example.com", "cdn.example.com"]

for host in hosts:
    # 随机选择一个浏览器指纹
    browser_name, config = random.choice(fingerprints)

    generator.set_config(config)
    client_hello = generator.generate_client_hello(host)

    print(f"主机: {host}")
    print(f"  使用指纹: {browser_name}")
    print(f"  ClientHello 大小: {len(client_hello)} bytes")
    print()
```

### 示例 3: TLS 1.3 Only 配置

```python
from tls_fingerprint import TLSFingerprintConfig, TLSFingerprintGenerator

# 创建仅支持 TLS 1.3 的配置
config = TLSFingerprintConfig()
config.version_min = 0x0304  # TLS 1.3
config.version_max = 0x0304  # TLS 1.3

# 仅使用 TLS 1.3 密码套件
config.cipher_suites = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
]

# TLS 1.3 签名算法
config.signature_algorithms = [
    0x0403,  # ECDSA_SECP256R1_SHA256
    0x0804,  # RSA_PSS_RSAE_SHA256
    0x0805,  # RSA_PSS_RSAE_SHA384
    0x0806,  # RSA_PSS_RSAE_SHA512
]

# 现代命名组
config.named_groups = [
    0x001D,  # x25519
]

# ALPN
config.alpn_protocols = ["h2"]

# 不使用 GREASE 和扩展随机化
config.enable_grease = False
config.permute_extensions = False

# 生成
generator = TLSFingerprintGenerator()
generator.set_config(config)
client_hello = generator.generate_client_hello("modern.example.com")

print(f"TLS 1.3 Only ClientHello: {len(client_hello)} bytes")
```

---

## 常见问题

### Q: 如何查看支持的密码套件常量？

```python
from tls_fingerprint import (
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
)

print(f"TLS_AES_128_GCM_SHA256 = 0x{TLS_AES_128_GCM_SHA256:04X}")
print(f"TLS_AES_256_GCM_SHA384 = 0x{TLS_AES_256_GCM_SHA384:04X}")
```

### Q: 生成的 ClientHello 可以直接用于网络请求吗？

生成的 ClientHello 是原始字节数据，需要配合底层 SSL/TLS 库（如 BoringSSL、OpenSSL）才能用于实际的网络连接。本库主要用于：

1. 生成指纹配置
2. 分析 TLS 指纹
3. 模拟浏览器 TLS 特征

### Q: 如何禁用 GREASE 扩展？

```python
config = BrowserFingerprints.chrome_desktop()
config.enable_grease = False  # 禁用 GREASE
```

### Q: 为什么 Firefox 和 Chrome 的指纹不同？

不同浏览器有不同的 TLS 实现：

- **Chrome**: 使用 BoringSSL，支持 GREASE
- **Firefox**: 使用 NSS，不支持 GREASE
- **Safari**: 使用 Secure Transport，有不同的默认配置

### Q: 如何验证指纹是否正确？

可以使用 Wireshark 抓包或在线 TLS 指纹分析工具来验证生成的 ClientHello 是否符合预期。

---

## 常量参考

### 密码套件常量

| 常量 | 值 | 说明 |
|------|------|------|
| `TLS_AES_128_GCM_SHA256` | 0x1301 | TLS 1.3 |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | TLS 1.3 |
| `TLS_CHACHA20_POLY1305_SHA256` | 0x1303 | TLS 1.3 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 0xC02B | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 0xC02F | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 0xC02C | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 0xC030 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | 0xCCA9 | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | 0xCCA8 | TLS 1.2 |

### 签名算法常量

| 常量 | 值 | 说明 |
|------|------|------|
| `ECDSA_SECP256R1_SHA256` | 0x0403 | ECDSA with SHA-256 |
| `RSA_PSS_RSAE_SHA256` | 0x0804 | RSA-PSS with SHA-256 |
| `RSA_PKCS1_SHA256` | 0x0401 | RSA-PKCS1 with SHA-256 |
| `ECDSA_SECP384R1_SHA384` | 0x0503 | ECDSA with SHA-384 |
| `RSA_PSS_RSAE_SHA384` | 0x0805 | RSA-PSS with SHA-384 |
| `RSA_PSS_RSAE_SHA512` | 0x0806 | RSA-PSS with SHA-512 |

### 命名组常量

| 常量 | 值 | 说明 |
|------|------|------|
| `X25519` | 0x001D | Curve25519 |
| `SECP256R1` | 0x0017 | NIST P-256 |
| `SECP384R1` | 0x0018 | NIST P-384 |
| `SECP521R1` | 0x0019 | NIST P-521 |

---

## 版本历史

- **1.0.0** - 初始版本
  - 支持 Chrome、Firefox、Safari、Edge 指纹
  - ClientHello 生成
  - 浏览器识别
