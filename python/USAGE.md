# TLS Fingerprint Library 使用指南

基于 BoringSSL 的 TLS 指纹库，支持浏览器指纹模拟和随机指纹生成。

## 安装

```bash
cd tls_for_python
sh build.sh
```

---

## 快速开始

### 1. 最简单的用法

```python
from tls_fingerprint import TLSHttpClient

# 创建客户端（使用随机浏览器指纹）
client = TLSHttpClient(browser_type="random")

# 发送请求
response = client.get("https://example.com")
print(f"状态码: {response.status_code}")
print(f"响应: {response.text}")
```

### 2. 指定浏览器类型

```python
from tls_fingerprint import TLSHttpClient

# 支持: chrome, firefox, safari, edge, chrome_android, random
client = TLSHttpClient(browser_type="chrome")
response = client.get("https://example.com")
```

### 3. 使用代理

```python
from tls_fingerprint import TLSHttpClient

# HTTP 代理
client = TLSHttpClient(browser_type="chrome", proxy="http://127.0.0.1:7890")

# SOCKS5 代理
client = TLSHttpClient(browser_type="chrome", proxy="socks5://127.0.0.1:1080")

# 带认证
client = TLSHttpClient(browser_type="chrome", proxy="http://user:password@proxy.example.com:8080")

response = client.get("https://example.com")
```

### 4. POST 请求

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")

# JSON
response = client.post("https://api.example.com/data", json={"key": "value"})

# 表单
response = client.post("https://api.example.com/form", body={"username": "test"})

# 原始数据
response = client.post("https://api.example.com/raw", body=b"raw data")
```

---

## HTTP 方法

```python
response = client.get(url, headers={...})
response = client.post(url, body=..., json=..., headers={...})
response = client.put(url, body=..., headers={...})
response = client.delete(url, headers={...})
response = client.head(url, headers={...})
```

## Response 对象

```python
response.status_code   # HTTP 状态码 (int)
response.headers       # 响应头 (dict)
response.body          # 响应体 (bytes)
response.text          # 响应体 (str)
response.json()        # 解析 JSON
```

---

## 浏览器指纹类型

| 类型 | 说明 |
|------|------|
| `chrome` | Chrome Desktop |
| `chrome_android` | Chrome Android |
| `firefox` | Firefox Desktop |
| `safari` | Safari macOS |
| `edge` | Microsoft Edge |
| `random` | 随机选择（每次创建客户端时固定） |

---

## 高级用法

### 查看当前指纹

```python
from tls_fingerprint import TLSHttpClient

client = TLSHttpClient(browser_type="chrome")
session = client.session

print(f"浏览器类型: {session.browser_type}")
print(f"JA3 指纹: {session.get_ja3_hash()}")

# 查看配置
config = session.config
print(f"密码套件: {[hex(c) for c in config.cipher_suites]}")
print(f"签名算法: {[hex(s) for s in config.signature_algorithms]}")
print(f"命名组: {[hex(g) for g in config.named_groups]}")
```

### 指纹池轮换

```python
from tls_fingerprint import TLSFingerprintPool, TLSHttpClient

pool = TLSFingerprintPool()

for url in urls:
    # 每5个请求换一个指纹
    session = pool.get_next()
    client = TLSHttpClient(session=session)
    response = client.get(url)
```

### 完全自定义指纹

```python
from tls_fingerprint import TLSFingerprintConfig, BoringSSLSocket

# 创建配置
config = TLSFingerprintConfig()
config.cipher_suites = [0x1301, 0x1302, 0xC02F, 0xC030]
config.signature_algorithms = [0x0403, 0x0804]
config.named_groups = [0x001D, 0x0017]  # X25519, P-256
config.alpn_protocols = ["http/1.1"]
config.enable_grease = True

# 使用
sock = BoringSSLSocket()
sock.set_config(config)
sock.set_debug(True)  # 开启调试日志

if sock.connect("example.com", 443, 10000) == 0:
    sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    response = sock.recv(8192)
    print(response[:100])

    # 获取调试日志
    print(sock.get_debug_log())
    sock.close()
```

---

## 常量参考

### 密码套件

```python
# TLS 1.3
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

# TLS 1.2
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
TLS_ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 = 0xCCA9
TLS_ECDHE_RSA_CHACHA20_POLY1305_SHA256 = 0xCCA8
```

### 签名算法

```python
ECDSA_SECP256R1_SHA256 = 0x0403
ECDSA_SECP384R1_SHA384 = 0x0503
RSA_PSS_RSAE_SHA256 = 0x0804
RSA_PSS_RSAE_SHA384 = 0x0805
RSA_PKCS1_SHA256 = 0x0401
```

### 命名组

```python
X25519 = 0x001D
SECP256R1 = 0x0017  # P-256
SECP384R1 = 0x0018  # P-384
SECP521R1 = 0x0019  # P-521
```

---

## 常见问题

**Q: 如何确保同一次会话中指纹不变？**

A: `TLSHttpClient` 在创建时固定指纹，多次请求使用相同指纹：

```python
client = TLSHttpClient(browser_type="random")
# 这3个请求使用相同的指纹
response1 = client.get("https://example.com/a")
response2 = client.get("https://example.com/b")
response3 = client.get("https://example.com/c")
```

**Q: 如何开启调试日志？**

A: 使用 `BoringSSLSocket` 时调用 `set_debug(True)`：

```python
sock = BoringSSLSocket()
sock.set_debug(True)  # 开启调试
# ... 连接后
print(sock.get_debug_log())  # 获取日志
```

**Q: 为什么某些网站连接失败？**

A: 确保使用标准浏览器指纹（chrome/firefox 等），检查网络和代理设置。
