# TLS Fingerprint Library - Python 使用说明

本文档详细介绍如何在 Python 中使用 TLS 指纹库来模拟浏览器 TLS 指纹。

---

## 目录

- [安装](#安装)
- [可用功能](#可用功能)
- [快速开始](#快速开始)
- [API 参考](#api-参考)
- [浏览器指纹预设](#浏览器指纹预设)
- [HTTP/2 指纹](#http2-指纹)
- [自定义指纹配置](#自定义指纹配置)
- [高级用法](#高级用法)
- [调试与排查](#调试与排查)
- [完整示例](#完整示例)
- [常见问题](#常见问题)

---

## 安装

### 方式一：从源码编译安装（推荐）

```bash
cd boringssl_tls_for_python

# 完整构建（编译 BoringSSL + C++ 扩展 + 打包）
./build.sh --clean

# 生成的 wheel 文件位于：
# python/dist/tls_fingerprint-1.0.0-py3-none-any.whl
```

> **注意**: 构建脚本会自动检测 `.venv` 虚拟环境，优先使用虚拟环境中的 Python。

### 方式二：安装 Wheel

```bash
pip3 install python/dist/tls_fingerprint-1.0.0-py3-none-any.whl
```

### 验证安装

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome", debug=True)
response = client.get("https://httpbin.org/get")
print(f"Status: {response.status_code}")
print(f"Body: {response.text[:200]}")
```

### 依赖

- Python 3.8+
- `hpack` — HTTP/2 头部编码/解码（必需）
- `brotli` — Brotli 解压缩（可选，用于 `content-encoding: br` 响应）

```bash
pip install hpack brotli
```

### 卸载

```bash
pip3 uninstall tls-fingerprint
```

---

## 可用功能

### HTTP 客户端（推荐入口）

| 类/函数 | 说明 |
|------|------|
| `TLSHttpClient` | HTTP 客户端，支持自定义 TLS 指纹、HTTP/2、代理 |
| `ProxyConfig` | 代理配置类（HTTP/HTTPS/SOCKS5） |
| `HttpResponse` | HTTP 响应对象 |
| `http_get(url, browser_type, proxy)` | 快速 GET 请求 |
| `http_post(url, browser_type, proxy, body)` | 快速 POST 请求 |

### 会话管理

| 类/函数 | 说明 |
|------|------|
| `TLSSession` | TLS 会话类，同一会话保持相同指纹 |
| `TLSClient` | 多会话管理器 |
| `TLSFingerprintPool` | 预生成指纹池，高性能场景使用 |
| `create_session(browser_type)` | 快速创建会话 |
| `create_random_session()` | 快速创建随机指纹会话 |

### 核心类

| 类 | 说明 |
|------|------|
| `TLSFingerprintConfig` | TLS 指纹配置类 |
| `TLSFingerprintGenerator` | ClientHello 生成器 |
| `TLSFingerprintAnalyzer` | TLS 指纹分析器 |
| `BrowserFingerprints` | 浏览器指纹预设工厂 |

---

## 快速开始

### 发送 HTTPS 请求（最常用）

```python
from tls_fingerprint import TLSHttpClient

# 创建客户端 — 模拟 Chrome TLS + HTTP/2 指纹
client = TLSHttpClient(browser_type="chrome")

# GET 请求
response = client.get("https://httpbin.org/get")
print(f"Status: {response.status_code}")
print(f"Body: {response.text}")

# POST 请求
response = client.post(
    "https://httpbin.org/post",
    body={"key": "value"}
)
print(response.json())
```

### 使用代理

```python
from tls_fingerprint import TLSHttpClient

# HTTP 代理
client = TLSHttpClient(browser_type="chrome", proxy="http://127.0.0.1:7897")

# SOCKS5 代理
client = TLSHttpClient(browser_type="firefox", proxy="socks5://127.0.0.1:1080")

# 带认证的代理
client = TLSHttpClient(
    browser_type="random",
    proxy="http://user:password@proxy.example.com:8080"
)

response = client.get("https://httpbin.org/ip")
print(response.json())
```

### 开启调试日志

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome", debug=True)
response = client.get("https://httpbin.org/get")
# 调试日志输出到 stderr，包含 DNS 解析、连接、TLS 握手、HTTP/2 帧等详细耗时
```

### 不同浏览器指纹

```python
from tls_fingerprint import TLSHttpClient

# 可用指纹: chrome, firefox, safari, edge, random
for browser in ["chrome", "firefox", "safari"]:
    client = TLSHttpClient(browser_type=browser)
    response = client.get("https://tls.peet.ws/api/all")
    data = response.json()
    print(f"{browser}: JA4={data.get('ja4', 'N/A')}")
```

---

## API 参考

### TLSHttpClient

支持自定义 TLS 指纹和 HTTP/2 指纹的 HTTP 客户端。

```python
client = TLSHttpClient(
    browser_type="chrome",      # chrome, firefox, safari, edge, random
    session=None,               # 可选：TLSSession 实例（覆盖 browser_type）
    proxy=None,                 # 可选：代理 URL 或 ProxyConfig
    timeout=30.0,               # 请求超时（秒）
    default_headers=None,       # 默认请求头
    debug=False,                # 开启调试日志
)
```

#### 方法

| 方法 | 说明 |
|------|------|
| `get(url, headers=None)` | GET 请求 |
| `post(url, headers=None, body=None)` | POST 请求 |
| `put(url, headers=None, body=None)` | PUT 请求 |
| `delete(url, headers=None)` | DELETE 请求 |
| `head(url, headers=None)` | HEAD 请求 |
| `request(method, url, headers=None, body=None)` | 通用请求 |
| `set_proxy(proxy)` | 设置代理 |
| `clear_proxy()` | 清除代理 |

#### 工作流程

```
request()
  ├── DNS 解析 (Python, IPv4 only, getaddrinfo)
  ├── 创建 BoringSSLSocket (C++ via pybind11)
  ├── 传递预解析 IP (跳过 C++ 层重复 DNS)
  ├── TCP 连接
  ├── TLS 握手 (BoringSSL, 应用浏览器指纹配置)
  │     ├── 密码套件、签名算法、命名组
  │     ├── GREASE / 扩展排列 / ALPS / ECH
  │     ├── 浏览器特定扩展 (record_size_limit, delegated_credentials 等)
  │     └── 自定义扩展顺序 (Safari)
  ├── ALPN 协商
  │     ├── h2 → HTTP/2 路径
  │     └── http/1.1 → HTTP/1.1 路径
  └── HTTP/2 路径:
        ├── Connection Preface
        ├── SETTINGS (浏览器特定参数)
        ├── WINDOW_UPDATE (浏览器特定值)
        ├── HEADERS 帧 (浏览器特定伪头顺序)
        └── 读取响应
```

### HttpResponse

```python
response = client.get("https://example.com")

response.status_code     # int: 200, 404, ...
response.headers         # dict: {"content-type": "...", ...}
response.body            # bytes: 原始响应体
response.text            # str: UTF-8 解码后的文本
response.json()          # Any: 解析 JSON
response.http_version    # str: "HTTP/2" 或 "HTTP/1.1"
```

### ProxyConfig

```python
from tls_fingerprint import ProxyConfig

# 从 URL 创建
proxy = ProxyConfig.from_url("socks5://user:pass@127.0.0.1:1080")

# 手动创建
proxy = ProxyConfig(
    host="127.0.0.1",
    port=1080,
    proxy_type="socks5",    # http, https, socks5
    username="user",
    password="pass",
)
```

### TLSSession

创建会话，同一会话的所有请求使用相同的 TLS 指纹。

```python
from tls_fingerprint import TLSSession

session = TLSSession(browser_type="random")

print(f"Session ID: {session.session_id}")
print(f"Browser: {session.browser_type}")
print(f"JA3 Hash: {session.get_ja3_hash()}")

# 与 TLSHttpClient 一起使用
client = TLSHttpClient(session=session)
```

### TLSClient — 多会话管理

```python
from tls_fingerprint import TLSClient

client = TLSClient(default_browser="chrome")

session1 = client.create_session("chrome")
session2 = client.create_session("firefox")

for info in client.list_sessions():
    print(f"Session: {info['session_id']}, Browser: {info['browser_type']}")
```

### TLSFingerprintPool — 指纹池

```python
from tls_fingerprint import TLSFingerprintPool

pool = TLSFingerprintPool(
    pool_size=20,
    browser_types=["chrome", "firefox", "safari"]
)

session = pool.get_random()   # 随机获取
session = pool.get_next()     # 轮询获取
pool.refresh()                # 刷新池
```

### 便捷函数

```python
from tls_fingerprint import http_get, http_post, create_session

# 快速 GET
response = http_get("https://httpbin.org/ip", browser_type="chrome")

# 快速 POST
response = http_post("https://httpbin.org/post", body={"key": "value"})

# 快速创建会话
session = create_session("firefox")
```

---

## 浏览器指纹预设

### 指纹对比

| 特征 | Chrome 131+ | Firefox 133+ | Safari 17+ | Edge |
|------|-------------|--------------|------------|------|
| **密码套件** | 15 个 | 15 个 | 7 个 | 同 Chrome |
| **签名算法** | 13 个 | 11 个 | 9 个 | 同 Chrome |
| **命名组** | 5 个 | 5 个 | 4 个 | 同 Chrome |
| **后量子密钥交换** | X25519MLKEM768 | X25519MLKEM768 | 不支持 | 同 Chrome |
| **GREASE** | 启用 | 禁用 | 启用 | 同 Chrome |
| **扩展排列** | 随机排列 | 固定顺序 | 自定义顺序 | 同 Chrome |
| **ALPS 扩展** | 发送 (0x4469) | 不发送 | 不发送 | 同 Chrome |
| **delegated_credentials** | 不发送 | 发送 (ext 34) | 不发送 | 不发送 |
| **record_size_limit** | 不发送 | 发送 (ext 28, 值=16385) | 不发送 | 不发送 |
| **cert_compression** | Brotli | Brotli | Brotli | Brotli |
| **ALPN** | h2, http/1.1 | h2, http/1.1 | h2, http/1.1 | h2, http/1.1 |

### Chrome 桌面版 (131+)

```python
config = BrowserFingerprints.chrome_desktop()
```

- TLS 引擎: BoringSSL
- 15 个密码套件 (TLS 1.3 × 3 + TLS 1.2 × 12)
- 13 个签名算法
- 5 个命名组: X25519MLKEM768, X25519, P-256, P-384, P-521
- GREASE 启用，扩展随机排列
- 发送 ALPS (ext 17513) — Chrome 独有
- 发送 compress_certificate (ext 27, Brotli)

### Firefox 桌面版 (133+)

```python
config = BrowserFingerprints.firefox_desktop()
```

- TLS 引擎: NSS
- 15 个密码套件
- 11 个签名算法
- 5 个命名组: X25519MLKEM768, X25519, P-256, P-384, P-521
- 不使用 GREASE，不随机排列扩展
- 发送 delegated_credentials (ext 34) — Firefox 独有
- 发送 record_size_limit (ext 28, 值=16385) — Firefox 独有
- 发送 compress_certificate (ext 27, Brotli)

### Safari (17+)

```python
config = BrowserFingerprints.safari()
```

- TLS 引擎: Secure Transport
- 7 个密码套件 (无 CHACHA20-POLY1305 TLS 1.2 套件)
- 9 个签名算法 (按密钥长度交错排列)
- 4 个命名组: X25519, P-256, P-384, P-521 (无后量子)
- GREASE 启用，使用自定义扩展顺序（非随机）
- 自定义扩展顺序: SNI → groups → ec_point → sigalgs → EMS → renegotiate → ticket → SCT → OCSP → versions → psk_modes → key_share → ALPN → cert_compress
- 发送 compress_certificate (ext 27, Brotli)

### Edge

```python
config = BrowserFingerprints.edge()
```

- 与 Chrome 完全相同（基于 Chromium + BoringSSL）

---

## HTTP/2 指纹

当服务器通过 ALPN 协商到 `h2` 协议时，库会自动使用 HTTP/2 通信，并应用浏览器特定的 HTTP/2 指纹。

### HTTP/2 指纹对比

| 特征 | Chrome | Firefox | Safari | Edge |
|------|--------|---------|--------|------|
| **SETTINGS 数量** | 7 | 5 | 5 | 7 |
| **HEADER_TABLE_SIZE** | 65536 | 65536 | 默认 | 65536 |
| **ENABLE_PUSH** | 0 | 不发送 | 0 | 0 |
| **MAX_CONCURRENT_STREAMS** | 1000 | 100 | 100 | 1000 |
| **INITIAL_WINDOW_SIZE** | 6291456 | 131072 | 2097152 | 6291456 |
| **MAX_HEADER_LIST_SIZE** | 262144 | 262144 | 262144 | 262144 |
| **UNKNOWN_SETTING_8** | 1 | 不发送 | 不发送 | 1 |
| **WINDOW_UPDATE** | 15663105 | 12517377 | 10485760 | 15663105 |
| **伪头顺序** | :method, :authority, :scheme, :path | :method, :path, :authority, :scheme | :method, :scheme, :path, :authority | 同 Chrome |

> **伪头顺序**是 Akamai / Cloudflare 等 CDN 用于 HTTP/2 指纹检测的重要特征。本库为每种浏览器实现了正确的伪头顺序。

---

## 自定义指纹配置

### 创建自定义配置

```python
from tls_fingerprint import TLSFingerprintConfig, TLSFingerprintGenerator

config = TLSFingerprintConfig()

# TLS 版本
config.version_min = 0x0303  # TLS 1.2
config.version_max = 0x0304  # TLS 1.3

# 密码套件
config.cipher_suites = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    0xC02B,  # ECDHE-ECDSA-AES128-GCM-SHA256
    0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
]

# 签名算法
config.signature_algorithms = [
    0x0403,  # ECDSA_SECP256R1_SHA256
    0x0804,  # RSA_PSS_RSAE_SHA256
    0x0401,  # RSA_PKCS1_SHA256
]

# 命名组
config.named_groups = [
    0x001D,  # x25519
    0x0017,  # secp256r1
]

# ALPN
config.alpn_protocols = ["h2", "http/1.1"]

# 行为
config.permute_extensions = True
config.enable_grease = True
```

### 修改预设配置

```python
from tls_fingerprint import BrowserFingerprints

# 基于 Chrome 预设修改
config = BrowserFingerprints.chrome_desktop()
config.enable_grease = False        # 禁用 GREASE
config.permute_extensions = False   # 禁用扩展随机排列

# 使用修改后的配置
client = TLSHttpClient(session=TLSSession(config=config))
```

---

## 高级用法

### 多账户多指纹

```python
from tls_fingerprint import TLSHttpClient, TLSSession

accounts = {}
for user in ["user1", "user2", "user3"]:
    session = TLSSession(browser_type="random")
    accounts[user] = TLSHttpClient(session=session)
    print(f"{user}: {session.browser_type} (session={session.session_id[:8]})")

# 每个账户始终使用相同的 TLS 指纹
r1 = accounts["user1"].get("https://httpbin.org/ip")
r2 = accounts["user2"].get("https://httpbin.org/ip")
```

### 动态切换代理

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

# 通过代理 1
client.set_proxy("http://127.0.0.1:8080")
r1 = client.get("https://httpbin.org/ip")

# 切换到代理 2
client.set_proxy("socks5://127.0.0.1:1080")
r2 = client.get("https://httpbin.org/ip")

# 直连
client.clear_proxy()
r3 = client.get("https://httpbin.org/ip")
```

### 爬虫示例

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://127.0.0.1:7897",
    timeout=10.0,
    default_headers={
        "Referer": "https://www.google.com/",
    },
)

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

### POST JSON 数据

```python
import json
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

response = client.post(
    "https://httpbin.org/post",
    headers={"Content-Type": "application/json"},
    body=json.dumps({"key": "value"}).encode()
)
print(response.json())
```

### POST 表单数据

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

# body 传入 dict 自动编码为 application/x-www-form-urlencoded
response = client.post(
    "https://httpbin.org/post",
    body={"username": "test", "password": "123456"}
)
print(response.json())
```

---

## 调试与排查

### 开启调试模式

```python
client = TLSHttpClient(browser_type="chrome", debug=True)
response = client.get("https://httpbin.org/get")
```

调试日志输出到 stderr，包含：
- DNS 解析时间
- TCP 连接时间
- TLS 握手时间（包括协商的密码套件和 TLS 版本）
- ALPN 协议协商结果
- HTTP/2 帧收发（SETTINGS、HEADERS、DATA、WINDOW_UPDATE）
- 总请求耗时

示例输出：
```
[12:00:01] [TLS] === Starting GET request to https://httpbin.org/get ===
[12:00:01] [TLS] Target: httpbin.org:443, path=/get, https=True
[12:00:01] [TLS] Resolving DNS for httpbin.org...
[12:00:01] [TLS] DNS resolved: httpbin.org -> 52.71.170.232 (0.013s)
[12:00:01] [TLS] Connecting directly to httpbin.org:443...
[12:00:01] [TLS] Using pre-resolved IP: 52.71.170.232
[12:00:02] [TLS] Direct connection established in 1.203s
[12:00:02] [TLS] Negotiated ALPN protocol: h2
[12:00:02] [TLS] Using HTTP/2 protocol
[12:00:02] [TLS] Sent HTTP/2 connection preface + SETTINGS + WINDOW_UPDATE
[12:00:02] [TLS] Sent SETTINGS ACK
[12:00:02] [TLS] Sent HTTP/2 HEADERS frame
[12:00:02] [TLS] === Request completed in 1.542s (status: 200) ===
```

### 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| `ImportError: _tls_fingerprint` | C++ 扩展未编译 | `cd python && python setup.py build_ext --inplace` |
| `ImportError: hpack` | 缺少依赖 | `pip install hpack` |
| 请求超时 | 网络问题或代理不可用 | 检查代理配置，尝试直连 |
| SSL handshake failed | 服务器不支持配置的密码套件 | 换用其他浏览器指纹 |
| 9 秒+延迟 | DNS 解析问题（旧版本） | 更新到最新版本（已修复） |

---

## 架构说明

### 双层架构

```
Python 层                          C++ 层 (pybind11)
─────────────────────            ──────────────────────────
TLSHttpClient                    BoringSSLSocket
├── DNS 解析 (IPv4)              ├── TCP 连接 (使用预解析 IP)
├── HTTP/2 指纹帧构造              ├── TLS 握手 (BoringSSL)
├── 请求/响应处理                  │   ├── 浏览器指纹配置
├── 代理协商                      │   ├── GREASE / 扩展排列
└── gzip/brotli 解压              │   ├── ALPS / ECH / SCT
                                 │   └── 自定义扩展顺序
                                 └── SSL 读写
```

### 源码同步

项目维护两套 C++ 源码，必须保持同步：

| 路径 | 用途 |
|------|------|
| `src/boringssl_socket.cc` | 独立 C++ 库 |
| `python/src/boringssl_socket.cc` | Python 扩展 |
| `include/tls_fingerprint/` | 独立库头文件 |
| `python/include/tls_fingerprint/` | Python 扩展头文件 |

### BoringSSL 补丁

本库对 BoringSSL 源码进行了以下补丁：

| 补丁 | 文件 | 说明 |
|------|------|------|
| record_size_limit 扩展 | `ssl/extensions.cc`, `ssl/internal.h`, `ssl/ssl_lib.cc` | 添加 ext 28 支持 (RFC 8449) |
| 自定义扩展顺序 | `ssl/extensions.cc`, `ssl/internal.h`, `ssl/ssl_lib.cc` | `SSL_set_extension_order()` API |
| X25519MLKEM768 | BoringSSL 已内置 | 后量子混合密钥交换 (group 4588) |

---

## 常量参考

### 密码套件

| 值 | 名称 | TLS 版本 |
|------|------|------|
| 0x1301 | TLS_AES_128_GCM_SHA256 | 1.3 |
| 0x1302 | TLS_AES_256_GCM_SHA384 | 1.3 |
| 0x1303 | TLS_CHACHA20_POLY1305_SHA256 | 1.3 |
| 0xC02B | ECDHE-ECDSA-AES128-GCM-SHA256 | 1.2 |
| 0xC02F | ECDHE-RSA-AES128-GCM-SHA256 | 1.2 |
| 0xC02C | ECDHE-ECDSA-AES256-GCM-SHA384 | 1.2 |
| 0xC030 | ECDHE-RSA-AES256-GCM-SHA384 | 1.2 |
| 0xCCA9 | ECDHE-ECDSA-CHACHA20-POLY1305 | 1.2 |
| 0xCCA8 | ECDHE-RSA-CHACHA20-POLY1305 | 1.2 |
| 0xC013 | ECDHE-RSA-AES128-SHA | 1.2 |
| 0xC014 | ECDHE-RSA-AES256-SHA | 1.2 |
| 0x009C | AES128-GCM-SHA256 | 1.2 |
| 0x009D | AES256-GCM-SHA384 | 1.2 |
| 0x002F | AES128-SHA | 1.2 |
| 0x0035 | AES256-SHA | 1.2 |

### 签名算法

| 值 | 名称 |
|------|------|
| 0x0403 | ECDSA_SECP256R1_SHA256 |
| 0x0804 | RSA_PSS_RSAE_SHA256 |
| 0x0401 | RSA_PKCS1_SHA256 |
| 0x0503 | ECDSA_SECP384R1_SHA384 |
| 0x0805 | RSA_PSS_RSAE_SHA384 |
| 0x0501 | RSA_PKCS1_SHA384 |
| 0x0806 | RSA_PSS_RSAE_SHA512 |
| 0x0601 | RSA_PKCS1_SHA512 |
| 0x0201 | RSA_PKCS1_SHA1 |

### 命名组

| 值 | 名称 | 说明 |
|------|------|------|
| 0x11EC (4588) | X25519MLKEM768 | 后量子混合密钥交换 |
| 0x001D | X25519 | Curve25519 |
| 0x0017 | secp256r1 | NIST P-256 |
| 0x0018 | secp384r1 | NIST P-384 |
| 0x0019 | secp521r1 | NIST P-521 |

---

## 版本历史

- **1.0.0** - 初始版本
  - 支持 Chrome 131+、Firefox 133+、Safari 17+、Edge 指纹
  - BoringSSL C++ 扩展 (pybind11)
  - HTTP/1.1 和 HTTP/2 协议支持
  - HTTP/2 浏览器指纹 (SETTINGS/WINDOW_UPDATE/伪头顺序)
  - TLS 扩展: GREASE, ALPS, delegated_credentials, record_size_limit, compress_certificate, 自定义扩展顺序
  - 后量子密钥交换: X25519MLKEM768
  - HTTP/HTTPS/SOCKS5 代理支持
  - DNS 预解析优化（避免 C++ 层重复解析）
  - IPv4 优先 DNS 解析（避免 IPv6 AAAA 查询延迟）
  - 调试日志模式
