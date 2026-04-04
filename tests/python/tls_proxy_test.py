"""
TLS Fingerprint 代理测试脚本
基于 USAGE.md 文档，测试 TLSHttpClient 的代理功能
"""
import time
import json
import argparse
from tls_fingerprint import (
    TLSSession,
    TLSClient,
    TLSFingerprintPool,
    TLSHttpClient,
    ProxyConfig,
    BrowserFingerprints,
    TLSFingerprintGenerator,
    create_session,
    create_random_session,
    generate_client_hello,
    http_get,
    http_post,
)

TEST_URL = "https://httpbin.org/ip"
POST_URL = "https://httpbin.org/post"
HEADERS_URL = "https://httpbin.org/headers"

BROWSER_TYPES = ["chrome", "firefox", "safari", "edge"]


def test_basic_no_proxy():
    """测试1: 无代理直连"""
    print("\n" + "=" * 60)
    print("测试1: 无代理直连")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome")
    response = client.get(TEST_URL)
    print(f"  Status: {response.status_code}")
    print(f"  Body: {response.text.strip()}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    print("  ✅ 通过")


def test_http_proxy(proxy_url):
    """测试2: HTTP 代理"""
    print("\n" + "=" * 60)
    print(f"测试2: HTTP 代理 - {proxy_url}")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome", proxy=proxy_url)
    response = client.get(TEST_URL)
    print(f"  Status: {response.status_code}")
    print(f"  Body: {response.text.strip()}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    print("  ✅ 通过")


def test_socks5_proxy(proxy_url):
    """测试3: SOCKS5 代理"""
    print("\n" + "=" * 60)
    print(f"测试3: SOCKS5 代理 - {proxy_url}")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome", proxy=proxy_url)
    response = client.get(TEST_URL)
    print(f"  Status: {response.status_code}")
    print(f"  Body: {response.text.strip()}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    print("  ✅ 通过")


def test_browser_fingerprint(proxy_url=None):
    """测试4: 不同浏览器指纹"""
    print("\n" + "=" * 60)
    print(f"测试4: 多浏览器指纹轮换 (proxy: {proxy_url or '直连'})")
    print("=" * 60)
    for bt in BROWSER_TYPES:
        client = TLSHttpClient(browser_type=bt, proxy=proxy_url)
        response = client.get(TEST_URL)
        print(f"  [{bt:>10}] Status: {response.status_code}, IP: {response.text.strip()}")
        assert response.status_code == 200
    print("  ✅ 全部通过")


def test_session_consistency(proxy_url=None):
    """测试5: 同一会话保持相同指纹"""
    print("\n" + "=" * 60)
    print(f"测试5: 会话一致性 (proxy: {proxy_url or '直连'})")
    print("=" * 60)
    session = TLSSession(browser_type="random")
    client = TLSHttpClient(session=session, proxy=proxy_url)
    print(f"  Session ID: {session.session_id}")
    print(f"  Browser: {session.browser_type}")
    print(f"  JA3 Hash: {session.get_ja3_hash()}")

    ja3 = session.get_ja3_hash()
    for url in [TEST_URL, HEADERS_URL]:
        client.get(url)
        current_ja3 = session.get_ja3_hash()
        assert current_ja3 == ja3, f"JA3 changed: {ja3} -> {current_ja3}"
        print(f"  {url} - JA3: {current_ja3}  ✅")
    print("  ✅ 会话指纹一致")


def test_proxy_switch():
    """测试6: 动态切换代理"""
    print("\n" + "=" * 60)
    print("测试6: 动态切换代理 (需要提供 --proxy1 和 --proxy2)")
    print("=" * 60)


def test_proxy_switch_proxies(proxy1, proxy2):
    """测试6: 动态切换代理（实际执行）"""
    print("\n" + "=" * 60)
    print("测试6: 动态切换代理")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome")

    client.set_proxy(proxy1)
    r1 = client.get(TEST_URL)
    print(f"  代理1 ({proxy1}): {r1.text.strip()}")

    client.set_proxy(proxy2)
    r2 = client.get(TEST_URL)
    print(f"  代理2 ({proxy2}): {r2.text.strip()}")

    client.clear_proxy()
    r3 = client.get(TEST_URL)
    print(f"  直连: {r3.text.strip()}")
    print("  ✅ 切换正常")


def test_post_request(proxy_url=None):
    """测试7: POST 请求"""
    print("\n" + "=" * 60)
    print(f"测试7: POST 请求 (proxy: {proxy_url or '直连'})")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome", proxy=proxy_url)

    # JSON POST
    data = json.dumps({"test": "hello", "time": time.time()}).encode()
    response = client.post(POST_URL, headers={"Content-Type": "application/json"}, body=data)
    result = response.json()
    print(f"  JSON POST Status: {response.status_code}")
    print(f"  Server received: {result.get('json', {})}")
    assert response.status_code == 200
    print("  ✅ 通过")


def test_pool(proxy_url=None):
    """测试8: 指纹池 + 代理"""
    print("\n" + "=" * 60)
    print(f"测试8: 指纹池 (pool_size=4, proxy: {proxy_url or '直连'})")
    print("=" * 60)
    pool = TLSFingerprintPool(pool_size=10, browser_types=BROWSER_TYPES)
    for i in range(10):
        session = pool.get_next()
        client = TLSHttpClient(session=session, proxy=proxy_url)
        response = client.get(TEST_URL)
        print(f"  [{i}] session={session.session_id[:8]}... browser={session.browser_type:>10} status={response.status_code}")
    print(f"  Pool size: {len(pool)}")
    print("  ✅ 通过")


def test_quick_functions(proxy_url=None):
    """测试9: 便捷函数 http_get / http_post"""
    print("\n" + "=" * 60)
    print(f"测试9: 便捷函数 (proxy: {proxy_url or '直连'})")
    print("=" * 60)
    r1 = http_get(TEST_URL, browser_type="firefox", proxy=proxy_url)
    print(f"  http_get: {r1.text.strip()}")
    assert r1.status_code == 200

    r2 = http_post(POST_URL, browser_type="chrome", proxy=proxy_url, body={"key": "value"})
    print(f"  http_post: status={r2.status_code}, json={r2.json().get('json', {})}")
    assert r2.status_code == 200
    print("  ✅ 通过")


def test_proxy_config_parse(proxy_url):
    """测试10: ProxyConfig 解析"""
    print("\n" + "=" * 60)
    print("测试10: ProxyConfig 解析")
    print("=" * 60)
    proxy = ProxyConfig.from_url(proxy_url)
    print(f"  host: {proxy.host}")
    print(f"  port: {proxy.port}")
    print(f"  type: {proxy.proxy_type}")
    if proxy.username:
        print(f"  user: {proxy.username}")
    if proxy.password:
        print(f"  pass: {proxy.password}")
    print("  ✅ 通过")


def test_generate_client_hello():
    """测试11: ClientHello 生成"""
    print("\n" + "=" * 60)
    print("测试11: ClientHello 生成（不发送请求）")
    print("=" * 60)
    for bt in BROWSER_TYPES:
        data = generate_client_hello("example.com", browser_type=bt)
        print(f"  {bt:>10}: {len(data)} bytes, hex={data[:16].hex()}...")
    print("  ✅ 通过")


def test_response_details(proxy_url=None):
    """测试12: HttpResponse 完整字段"""
    print("\n" + "=" * 60)
    print(f"测试12: HttpResponse 详情 (proxy: {proxy_url or '直连'})")
    print("=" * 60)
    client = TLSHttpClient(browser_type="chrome", proxy=proxy_url)
    response = client.get("https://httpbin.org/get")
    print(f"  status_code: {response.status_code}")
    print(f"  http_version: {response.http_version}")
    print(f"  headers keys: {list(response.headers.keys())[:5]}...")
    print(f"  body length: {len(response.body)} bytes")
    print(f"  text (first 100): {response.text[:100]}")
    data = response.json()
    print(f"  json origin: {data.get('origin')}")
    assert response.status_code == 200
    print("  ✅ 通过")


def run_all(proxy=None, proxy1=None, proxy2=None):
    """运行所有测试"""
    print("=" * 60)
    print(f"TLS Fingerprint 代理测试  |  proxy: {proxy or '无'}")
    print(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []
    tests = [
        ("1.  直连基础", lambda: test_basic_no_proxy()),
        ("2.  HTTP代理", lambda: test_http_proxy(proxy)) if proxy else None,
        ("3.  浏览器指纹", lambda: test_browser_fingerprint(proxy)),
        ("4.  会话一致性", lambda: test_session_consistency(proxy)),
        ("5.  POST请求", lambda: test_post_request(proxy)),
        ("6.  指纹池", lambda: test_pool(proxy)),
        ("7.  便捷函数", lambda: test_quick_functions(proxy)),
        ("8.  ProxyConfig解析", lambda: test_proxy_config_parse(proxy)) if proxy else None,
        ("9.  ClientHello生成", lambda: test_generate_client_hello()),
        ("10. Response详情", lambda: test_response_details(proxy)),
        ("11. 动态切换代理", lambda: test_proxy_switch_proxies(proxy1, proxy2)) if proxy1 and proxy2 else None,
    ]

    for t in tests:
        if t is None:
            continue
        name, fn = t
        try:
            start = time.time()
            fn()
            elapsed = time.time() - start
            results.append((name, "PASS", elapsed))
        except Exception as e:
            elapsed = time.time() - start
            results.append((name, "FAIL", elapsed))
            print(f"  ❌ 失败: {e}")

    # 汇总
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    passed = sum(1 for _, s, _ in results if s == "PASS")
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    for name, status, elapsed in results:
        icon = "✅" if status == "PASS" else "❌"
        print(f"  {icon} {name} ({elapsed:.2f}s)")
    print(f"\n  共 {len(results)} 项, 通过 {passed}, 失败 {failed}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Fingerprint 代理测试脚本")
    parser.add_argument("--proxy", type=str, default=None, help="代理地址, 如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080")
    parser.add_argument("--proxy1", type=str, default=None, help="动态切换测试-代理1")
    parser.add_argument("--proxy2", type=str, default=None, help="动态切换测试-代理2")
    parser.add_argument("--test", type=str, default=None, help="运行单个测试: basic/http/browser/session/post/pool/quick/config/hello/response/switch")
    args = parser.parse_args()

    p = args.proxy
    if args.test:
        mapping = {
            "basic": lambda: test_basic_no_proxy(),
            "http": lambda: test_http_proxy(p) if p else test_basic_no_proxy(),
            "browser": lambda: test_browser_fingerprint(p),
            "session": lambda: test_session_consistency(p),
            "post": lambda: test_post_request(p),
            "pool": lambda: test_pool(p),
            "quick": lambda: test_quick_functions(p),
            "config": lambda: test_proxy_config_parse(p) if p else print("  需要 --proxy"),
            "hello": lambda: test_generate_client_hello(),
            "response": lambda: test_response_details(p),
            "switch": lambda: test_proxy_switch_proxies(args.proxy1, args.proxy2) if args.proxy1 and args.proxy2 else test_proxy_switch(),
        }
        fn = mapping.get(args.test)
        if fn:
            fn()
        else:
            print(f"未知测试: {args.test}")
            print(f"可选: {', '.join(mapping.keys())}")
    else:
        run_all(proxy=p, proxy1=args.proxy1, proxy2=args.proxy2)
