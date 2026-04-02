# TLS Fingerprint Library 使用文档

基于 BoringSSL 的 TLS 指纹库，完全使用 BoringSSL 进行 TLS 连接，支持自定义和随机化 TLS 指纹。

## 特性

- ✅ **完全使用 BoringSSL** - 所有 TLS 操作均使用 BoringSSL
- ✅ **浏览器指纹模拟** - 支持 Chrome, Firefox, Safari, Edge 等浏览器指纹
- ✅ **随机指纹生成** - 支持生成海量合法 TLS 指纹组合
- ✅ **指纹池管理** - 支持指纹池的随机获取和轮询
- ✅ **完全自定义** - 支持自定义密码套件、签名算法、命名组等

## 安装

```bash
cd tls_for_python
sh build.sh
```

---

## 快速开始

### 1. 最简单的使用方式

```python
from tls_fingerprint import TLSHttpClient

# 使用随机浏览器指纹
client = TLSHttpClient(browser_type="random")
response = client.get("https://example.com")
print(f"状态码: {response.status_code}")
print(f"响应内容: {response.text}")
```

### 2. 指定浏览器类型

```python
from tls_fingerprint import TLSHttpClient

# 支持的浏览器类型: chrome, firefox, safari, edge, chrome_android, random
client = TLSHttpClient(browser_type="chrome")
response = client.get("https://example.com")
```

### 3. 使用代理

```python
from tls_fingerprint import TLSHttpClient

# HTTP 代理
client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://127.0.0.1:7890"
)

# SOCKS5 代理
client = TLSHttpClient(
    browser_type="chrome",
    proxy="socks5://127.0.0.1:1080"
)

# 带认证的代理
client = TLSHttpClient(
    browser_type="chrome",
    proxy="http://user:password@proxy.example.com:8080"
)

response = client.get("https://example.com")
```

### 4. POST 请求

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

# JSON 数据
response = client.post(
    "https://api.example.com/data",
    json={"key": "value"}
)

# 表单数据
response = client.post(
    "https://api.example.com/form",
    body={"username": "test", "password": "123456"}
)

# 原始字节
response = client.post(
    "https://api.example.com/raw",
    body=b"raw data",
    headers={"Content-Type": "application/octet-stream"}
)
```

---

## 核心 API

### TLSHttpClient

HTTP 客户端，封装了 BoringSSL TLS 连接。

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(
    browser_type="chrome",          # 浏览器类型
    proxy="http://127.0.0.1:7890",  # 代理 (可选)
    timeout=30.0,                   # 超时时间 (秒)
    default_headers={               # 默认请求头 (可选)
        "User-Agent": "Custom/1.0"
    }
)
```

**支持的浏览器类型:**
| 类型 | 说明 |
|------|------|
| `chrome` | Chrome Desktop |
| `chrome_android` | Chrome Android |
| `firefox` | Firefox Desktop |
| `safari` | Safari macOS |
| `edge` | Microsoft Edge |
| `random` | 随机选择 |

**HTTP 方法:**

```python
response = client.get(url, headers={...})
response = client.post(url, body=..., headers={...})
response = client.put(url, body=..., headers={...})
response = client.delete(url, headers={...})
response = client.head(url, headers={...})
```

**HttpResponse 对象:**

```python
response.status_code   # HTTP 状态码 (int)
response.headers       # 响应头 (dict)
response.body          # 响应体 (bytes)
response.text          # 响应体 (str)
response.json()        # 解析 JSON (dict)
```

---

### TLSFingerprintPool

TLS 指纹池，管理多个 TLS 指纹。

```python
from tls_fingerprint import TLSFingerprintPool

pool = TLSFingerprintPool()

# 查看指纹池大小
print(f"指纹池大小: {pool.size}")

# 随机获取一个指纹 (返回 TLSSession)
session = pool.get_random()

# 轮询获取指纹
session = pool.get_next()

# 刷新指纹池
pool.refresh()
```

---

### TLSSession

TLS 会话，封装了 TLS 指纹配置。

```python
from tls_fingerprint import create_session, create_random_session

# 创建指定浏览器的会话
session = create_session("chrome")

# 创建随机会话
session = create_random_session()

# 查看会话信息
print(f"会话ID: {session.session_id}")
print(f"浏览器类型: {session.browser_type}")
print(f"JA3 指纹: {session.get_ja3_hash()}")

# 获取配置
config = session.config
print(f"密码套件: {[hex(c) for c in config.cipher_suites]}")
print(f"签名算法: {[hex(s) for s in config.signature_algorithms]}")
print(f"命名组: {[hex(g) for g in config.named_groups]}")
```

---

## 自定义 TLS 指纹

### TLSFingerprintConfig

完全自定义 TLS 指纹配置。

```python
from tls_fingerprint import TLSFingerprintConfig, BoringSSLSocket

# 创建自定义配置
config = TLSFingerprintConfig()
config.version_min = 0x0303  # TLS 1.2
config.version_max = 0x0304  # TLS 1.3

# 设置密码套件
config.cipher_suites = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
]

# 设置签名算法
config.signature_algorithms = [
    0x0403,  # ECDSA_SECP256R1_SHA256
    0x0804,  # RSA_PSS_RSAE_SHA256
]

# 设置命名组 (椭圆曲线)
config.named_groups = [
    0x001D,  # X25519
    0x0017,  # SECP256R1 (P-256)
]

# 设置 ALPN 协议
config.alpn_protocols = ["h2", "http/1.1"]

# 其他选项
config.permute_extensions = True   # 随机排列扩展顺序
config.enable_grease = True        # 启用 GREASE 扩展

# 使用自定义配置
sock = BoringSSLSocket()
sock.set_config(config)
result = sock.connect("example.com", 443, 10000)
if result == 0:
    print("连接成功!")
    sock.close()
```

---

## 合法的 TLS 指纹元素

### 密码套件 (Cipher Suites)

**TLS 1.3:**
| 代码 | 名称 |
|------|------|
| `0x1301` | TLS_AES_128_GCM_SHA256 |
| `0x1302` | TLS_AES_256_GCM_SHA384 |
| `0x1303` | TLS_CHACHA20_POLY1305_SHA256 |

**TLS 1.2:**
| 代码 | 名称 |
|------|------|
| `0xC02B` | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| `0xC02F` | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| `0xC02C` | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 |
| `0xC030` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
| `0xCCA9` | TLS_ECDHE_ECDSA_CHACHA20_POLY1305 |
| `0xCCA8` | TLS_ECDHE_RSA_CHACHA20_POLY1305 |

### 签名算法 (Signature Algorithms)

| 代码 | 名称 |
|------|------|
| `0x0403` | ECDSA_SECP256R1_SHA256 |
| `0x0503` | ECDSA_SECP384R1_SHA384 |
| `0x0603` | ECDSA_SECP521R1_SHA512 |
| `0x0401` | RSA_PKCS1_SHA256 |
| `0x0501` | RSA_PKCS1_SHA384 |
| `0x0601` | RSA_PKCS1_SHA512 |
| `0x0804` | RSA_PSS_RSAE_SHA256 |
| `0x0805` | RSA_PSS_RSAE_SHA384 |
| `0x0806` | RSA_PSS_RSAE_SHA512 |

### 命名组 (Named Groups)

| 代码 | 名称 |
|------|------|
| `0x001D` | X25519 |
| `0x0017` | SECP256R1 (P-256) |
| `0x0018` | SECP384R1 (P-384) |
| `0x0019` | SECP521R1 (P-521) |

---

## BoringSSLSocket

底层 BoringSSL Socket，提供完整的 TLS 控制。

```python
from tls_fingerprint import BoringSSLSocket, BrowserFingerprints

# 创建 Socket
sock = BoringSSLSocket()

# 设置浏览器指纹
config = BrowserFingerprints.chrome_desktop()
sock.set_config(config)

# 连接服务器
result = sock.connect("example.com", 443, timeout_ms=10000)
if result == 0:
    # 获取连接信息
    info = sock.get_connection_info()
    print(f"密码套件: {info.cipher_suite}")
    print(f"TLS 版本: {info.version}")

    # 发送数据
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    sock.send(request)

    # 接收数据
    response = sock.recv(8192)
    print(f"响应: {response[:100]}")

    # 关闭连接
    sock.close()
else:
    print(f"连接失败: {sock.get_last_error()}")
```

### 通过代理连接

```python
from tls_fingerprint import BoringSSLSocket, BrowserFingerprints

sock = BoringSSLSocket()
sock.set_config(BrowserFingerprints.chrome_desktop())

# HTTP 代理
result = sock.connect_via_proxy(
    proxy_host="127.0.0.1",
    proxy_port=7890,
    target_host="example.com",
    target_port=443,
    proxy_type="http",  # 或 "socks5"
    timeout_ms=30000
)

if result == 0:
    print("代理连接成功!")
    sock.close()
```

---

## 完整示例

### 示例1: 爬虫使用随机指纹

```python
from tls_fingerprint import TLSHttpClient

def crawl(urls):
    """使用随机指纹爬取多个URL"""
    client = TLSHttpClient(browser_type="random")

    results = []
    for url in urls:
        try:
            response = client.get(url)
            results.append({
                "url": url,
                "status": response.status_code,
                "content": response.text
            })
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e)
            })

    return results

# 使用
urls = [
    "https://example.com/page1",
    "https://example.com/page2",
    "https://example.com/page3",
]
results = crawl(urls)
```

### 示例2: 多指纹轮换

```python
from tls_fingerprint import TLSFingerprintPool, TLSHttpClient

def crawl_with_rotation(urls):
    """使用指纹池轮换指纹"""
    pool = TLSFingerprintPool()

    results = []
    session = pool.get_next()

    for i, url in enumerate(urls):
        # 每5个请求换一个指纹
        if i % 5 == 0:
            session = pool.get_next()

        client = TLSHttpClient(session=session)
        try:
            response = client.get(url)
            results.append({
                "url": url,
                "status": response.status_code,
                "fingerprint": session.browser_type
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return results
```

### 示例3: 查看当前指纹信息

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")
session = client.session

print(f"浏览器类型: {session.browser_type}")
print(f"JA3 指纹: {session.get_ja3_hash()}")
print(f"详细信息: {session.to_dict()}")

# 查看配置
config = session.config
print(f"密码套件: {[hex(c) for c in config.cipher_suites]}")
print(f"签名算法: {[hex(s) for s in config.signature_algorithms]}")
print(f"命名组: {[hex(g) for g in config.named_groups]}")
print(f"ALPN: {config.alpn_protocols}")
```

---

## 常见问题

### Q: 为什么某些网站连接失败？

A: 部分网站的 TLS 配置可能与 BoringSSL 不完全兼容。建议：
1. 使用标准的浏览器指纹 (chrome, firefox 等)
2. 确保 BoringSSL 正确编译
3. 检查网络连接和代理设置

### Q: 如何确保指纹在一次会话中不变？

A: `TLSHttpClient` 在实例化时会固定指纹，多次请求使用相同指纹：

```python
client = TLSHttpClient(browser_type="random")

# 这3个请求使用相同的指纹
response1 = client.get("https://example.com/a")
response2 = client.get("https://example.com/b")
response3 = client.get("https://example.com/c")
```

### Q: 如何查看支持的常量？

```python
from tls_fingerprint import (
    # 密码套件常量
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    # 签名算法常量
    ECDSA_SECP256R1_SHA256,
    RSA_PSS_RSAE_SHA256,
    # 命名组常量
    X25519,
    SECP256R1,
    SECP384R1,
)

print(f"TLS_AES_128_GCM_SHA256 = {hex(TLS_AES_128_GCM_SHA256)}")
print(f"X25519 = {hex(X25519)}")
```

---

## 许可证

BSD 3-Clause License
