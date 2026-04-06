"""
TLS Fingerprint 全功能测试脚本
基于 USAGE.md 最新文档，覆盖所有 API 功能

用法:
    python tls_full_test.py                           # 运行全部测试（直连）
    python tls_full_test.py --proxy http://127.0.0.1:7897   # 通过 HTTP 代理
    python tls_full_test.py --proxy socks5://127.0.0.1:1080  # 通过 SOCKS5 代理
    python tls_full_test.py --test basic              # 运行单个测试
    python tls_full_test.py --list                    # 列出所有测试项
    python tls_full_test.py --debug                   # 开启调试日志
"""
import time
import json
import argparse
import traceback
import sys

from tls_fingerprint import (
    TLSHttpClient,
    TLSSession,
    TLSClient,
    TLSFingerprintPool,
    TLSFingerprintConfig,
    TLSFingerprintGenerator,
    TLSFingerprintAnalyzer,
    BrowserFingerprints,
    ProxyConfig,
    HttpResponse,
    http_get,
    http_post,
    create_session,
    create_random_session,
)

# ───────────────────────────────────────
# 常量
# ───────────────────────────────────────
GET_URL = "https://httpbin.org/get"
POST_URL = "https://httpbin.org/post"
IP_URL = "https://httpbin.org/ip"
HEADERS_URL = "https://httpbin.org/headers"
TLS_URL = "https://tls.peet.ws/api/all"
BROWSER_TYPES = ["chrome", "chrome_desktop", "chrome_android", "firefox", "firefox_desktop", "safari", "edge"]

# Delay between network tests to avoid httpbin.org rate limiting
INTER_TEST_DELAY = 1.0


def retry(fn, retries=2, delay=2.0):
    """Retry a callable up to `retries` times on ConnectionError/timeout."""
    last_err = None
    for attempt in range(1 + retries):
        try:
            return fn()
        except (ConnectionError, OSError) as e:
            last_err = e
            if attempt < retries:
                print(f"    [retry {attempt+1}/{retries}] {e}")
                time.sleep(delay)
    raise last_err


class TestResult:
    def __init__(self):
        self.results = []

    def add(self, name, passed, elapsed, detail=""):
        self.results.append((name, passed, elapsed, detail))

    def summary(self):
        print("\n" + "=" * 65)
        print("  测试汇总")
        print("=" * 65)
        passed = 0
        failed = 0
        for name, ok, elapsed, detail in self.results:
            icon = "PASS" if ok else "FAIL"
            print(f"  [{icon}] {name} ({elapsed:.2f}s)")
            if not ok and detail:
                print(f"         -> {detail}")
            if ok:
                passed += 1
            else:
                failed += 1
        total = passed + failed
        print(f"\n  共 {total} 项 | 通过 {passed} | 失败 {failed}")
        print("=" * 65)
        return failed == 0


result = TestResult()


def run_test(name):
    """测试装饰器"""
    def decorator(fn):
        fn._test_name = name
        return fn
    return decorator


# ───────────────────────────────────────
# 测试用例
# ───────────────────────────────────────

@run_test("1. 基础 GET 请求 (Chrome)")
def test_basic_get(proxy=None, debug=False):
    """USAGE.md - 快速开始: 发送 HTTPS 请求"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)
    response = client.get(GET_URL)
    assert response.status_code == 200, f"状态码异常: {response.status_code}"
    data = response.json()
    assert "origin" in data, "响应缺少 origin 字段"
    print(f"    Status: {response.status_code}")
    print(f"    HTTP Version: {response.http_version}")
    print(f"    Origin: {data['origin']}")


@run_test("2. 基础 POST 请求 (JSON)")
def test_post_json(proxy=None, debug=False):
    """USAGE.md - POST JSON 数据"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)
    payload = {"key": "value", "timestamp": int(time.time())}
    response = client.post(
        POST_URL,
        headers={"Content-Type": "application/json"},
        body=json.dumps(payload).encode()
    )
    assert response.status_code == 200, f"状态码异常: {response.status_code}"
    data = response.json()
    received = data.get("json", {})
    assert received.get("key") == "value", f"服务端未正确接收 JSON: {received}"
    print(f"    Status: {response.status_code}")
    print(f"    Server received JSON: {received}")


@run_test("3. POST 表单数据")
def test_post_form(proxy=None, debug=False):
    """USAGE.md - POST 表单数据 (dict 自动编码)"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)
    response = client.post(
        POST_URL,
        body={"username": "test_user", "password": "123456"}
    )
    assert response.status_code == 200
    data = response.json()
    form = data.get("form", {})
    assert form.get("username") == "test_user", f"表单数据异常: {form}"
    print(f"    Status: {response.status_code}")
    print(f"    Server received form: {form}")


@run_test("4. 多浏览器指纹测试")
def test_browser_fingerprints(proxy=None, debug=False):
    """USAGE.md - 不同浏览器指纹"""
    for browser in ["chrome", "firefox", "safari", "edge"]:
        client = TLSHttpClient(browser_type=browser, proxy=proxy, debug=debug)
        response = retry(lambda c=client: c.get(IP_URL))
        assert response.status_code == 200, f"{browser} 请求失败: {response.status_code}"
        ip_info = response.text.strip()
        print(f"    [{browser:>8}] Status: {response.status_code}, Response: {ip_info}")


@run_test("5. 随机指纹 (random)")
def test_random_fingerprint(proxy=None, debug=False):
    """USAGE.md - browser_type='random'"""
    client = TLSHttpClient(browser_type="random", proxy=proxy, debug=debug)
    response = retry(lambda: client.get(IP_URL))
    assert response.status_code == 200
    print(f"    Status: {response.status_code}")
    print(f"    Body: {response.text.strip()}")


@run_test("6. TLSSession 会话一致性")
def test_session_consistency(proxy=None, debug=False):
    """USAGE.md - TLSSession: 同一会话保持相同指纹"""
    session = TLSSession(browser_type="random")
    client = TLSHttpClient(session=session, proxy=proxy, debug=debug)

    ja3_initial = session.get_ja3_hash()
    print(f"    Session ID: {session.session_id}")
    print(f"    Browser: {session.browser_type}")
    print(f"    JA3 Hash: {ja3_initial}")

    # 发送多次请求，JA3 应保持不变
    for i, url in enumerate([IP_URL, HEADERS_URL, GET_URL]):
        client.get(url)
        ja3_now = session.get_ja3_hash()
        assert ja3_now == ja3_initial, f"第 {i+1} 次请求后 JA3 变化: {ja3_initial} -> {ja3_now}"
        print(f"    请求 {i+1}: JA3 一致 ({ja3_now[:16]}...)")


@run_test("7. TLSClient 多会话管理")
def test_multi_session(proxy=None, debug=False):
    """USAGE.md - TLSClient 多会话管理器"""
    client = TLSClient(default_browser="chrome")

    sessions = []
    for browser in ["chrome", "firefox", "safari"]:
        s = client.create_session(browser)
        sessions.append(s)
        print(f"    Created session: {s.session_id[:8]}... ({s.browser_type})")

    session_list = client.list_sessions()
    assert len(session_list) >= 3, f"会话数不足: {len(session_list)}"
    print(f"    Total sessions: {len(session_list)}")


@run_test("8. TLSFingerprintPool 指纹池")
def test_fingerprint_pool(proxy=None, debug=False):
    """USAGE.md - TLSFingerprintPool 预生成指纹池"""
    pool = TLSFingerprintPool(
        pool_size=5,
        browser_types=["chrome", "firefox", "safari"]
    )

    # get_random
    s1 = pool.get_random()
    print(f"    Random: session={s1.session_id[:8]}... browser={s1.browser_type}")

    # get_next (轮询)
    browsers_seen = set()
    for i in range(5):
        s = pool.get_next()
        browsers_seen.add(s.browser_type)
        print(f"    Next[{i}]: session={s.session_id[:8]}... browser={s.browser_type}")

    # refresh
    pool.refresh()
    s2 = pool.get_random()
    print(f"    After refresh: session={s2.session_id[:8]}... browser={s2.browser_type}")
    print(f"    Pool size: {len(pool)}")


@run_test("9. HttpResponse 完整字段验证")
def test_response_fields(proxy=None, debug=False):
    """USAGE.md - HttpResponse 属性验证"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)
    response = retry(lambda: client.get(GET_URL))

    # 验证所有属性存在且类型正确
    assert isinstance(response.status_code, int), "status_code 应为 int"
    assert isinstance(response.headers, dict), "headers 应为 dict"
    assert isinstance(response.body, bytes), "body 应为 bytes"
    assert isinstance(response.text, str), "text 应为 str"
    assert isinstance(response.http_version, str), "http_version 应为 str"

    data = response.json()
    assert isinstance(data, dict), "json() 应返回 dict"

    print(f"    status_code: {response.status_code} (int)")
    print(f"    http_version: {response.http_version}")
    print(f"    headers count: {len(response.headers)}")
    print(f"    body length: {len(response.body)} bytes")
    print(f"    text length: {len(response.text)} chars")
    print(f"    json keys: {list(data.keys())}")


@run_test("10. ProxyConfig 解析")
def test_proxy_config(proxy=None, debug=False):
    """USAGE.md - ProxyConfig.from_url 与手动创建"""
    # 测试 URL 解析
    test_urls = [
        "http://127.0.0.1:8080",
        "socks5://127.0.0.1:1080",
        "http://user:password@proxy.example.com:8080",
    ]
    for url in test_urls:
        pc = ProxyConfig.from_url(url)
        print(f"    {url}")
        print(f"      -> host={pc.host}, port={pc.port}, type={pc.proxy_type}")
        if pc.username:
            print(f"      -> auth: {pc.username}:{'*' * len(pc.password) if pc.password else 'N/A'}")

    # 手动创建
    pc2 = ProxyConfig(
        host="127.0.0.1",
        port=1080,
        proxy_type="socks5",
        username="user",
        password="pass",
    )
    assert pc2.host == "127.0.0.1"
    assert pc2.port == 1080
    assert pc2.proxy_type == "socks5"
    print(f"    Manual create: {pc2.host}:{pc2.port} ({pc2.proxy_type})")


@run_test("11. BrowserFingerprints 预设配置")
def test_browser_presets(proxy=None, debug=False):
    """USAGE.md - BrowserFingerprints 工厂方法"""
    presets = {
        "Chrome": BrowserFingerprints.chrome_desktop(),
        "Firefox": BrowserFingerprints.firefox_desktop(),
        "Safari": BrowserFingerprints.safari(),
        "Edge": BrowserFingerprints.edge(),
    }

    for name, config in presets.items():
        assert isinstance(config, TLSFingerprintConfig), f"{name} 返回类型错误"
        print(f"    [{name:>8}] ciphers={len(config.cipher_suites)}, "
              f"sigalgs={len(config.signature_algorithms)}, "
              f"groups={len(config.named_groups)}, "
              f"grease={config.enable_grease}, "
              f"permute={config.permute_extensions}")


@run_test("12. 自定义 TLS 指纹配置")
def test_custom_config(proxy=None, debug=False):
    """USAGE.md - 自定义指纹配置"""
    config = TLSFingerprintConfig()
    config.version_min = 0x0303  # TLS 1.2
    config.version_max = 0x0304  # TLS 1.3
    config.cipher_suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    config.signature_algorithms = [0x0403, 0x0804, 0x0401]
    config.named_groups = [0x001D, 0x0017]
    config.alpn_protocols = ["h2", "http/1.1"]
    config.permute_extensions = True
    config.enable_grease = True

    print(f"    version: 0x{config.version_min:04X} - 0x{config.version_max:04X}")
    print(f"    ciphers: {len(config.cipher_suites)}")
    print(f"    sigalgs: {len(config.signature_algorithms)}")
    print(f"    groups: {len(config.named_groups)}")
    print(f"    alpn: {config.alpn_protocols}")
    print(f"    grease: {config.enable_grease}, permute: {config.permute_extensions}")

    # 用自定义配置发送请求
    session = TLSSession(config=config)
    client = TLSHttpClient(session=session, proxy=proxy, debug=debug)
    response = client.get(IP_URL)
    assert response.status_code == 200, f"自定义配置请求失败: {response.status_code}"
    print(f"    请求成功: status={response.status_code}")


@run_test("13. 修改预设配置")
def test_modify_preset(proxy=None, debug=False):
    """USAGE.md - 基于预设修改配置"""
    config = BrowserFingerprints.chrome_desktop()
    original_grease = config.enable_grease
    original_permute = config.permute_extensions

    config.enable_grease = False
    config.permute_extensions = False

    print(f"    GREASE: {original_grease} -> {config.enable_grease}")
    print(f"    Permute: {original_permute} -> {config.permute_extensions}")

    session = TLSSession(config=config)
    client = TLSHttpClient(session=session, proxy=proxy, debug=debug)
    response = client.get(IP_URL)
    assert response.status_code == 200
    print(f"    修改后请求成功: status={response.status_code}")


@run_test("14. 便捷函数 http_get / http_post")
def test_convenience_functions(proxy=None, debug=False):
    """USAGE.md - 便捷函数"""
    r1 = http_get(IP_URL, browser_type="chrome", proxy=proxy)
    assert r1.status_code == 200
    print(f"    http_get: status={r1.status_code}, body={r1.text.strip()}")

    r2 = http_post(POST_URL, browser_type="firefox", body={"key": "test_value"}, proxy=proxy)
    assert r2.status_code == 200
    form_data = r2.json().get("form", r2.json().get("json", {}))
    print(f"    http_post: status={r2.status_code}, received={form_data}")


@run_test("15. create_session / create_random_session")
def test_create_session_helpers(proxy=None, debug=False):
    """USAGE.md - 快速创建会话"""
    s1 = create_session("firefox")
    assert s1.browser_type == "firefox", f"browser_type 不匹配: {s1.browser_type}"
    print(f"    create_session('firefox'): id={s1.session_id[:8]}..., browser={s1.browser_type}")

    s2 = create_random_session()
    assert s2.browser_type in BROWSER_TYPES, f"random 类型不在预期范围: {s2.browser_type}"
    print(f"    create_random_session(): id={s2.session_id[:8]}..., browser={s2.browser_type}")


@run_test("16. TLSFingerprintGenerator ClientHello 生成")
def test_client_hello_generator(proxy=None, debug=False):
    """USAGE.md - TLSFingerprintGenerator"""
    for browser in ["chrome", "firefox", "safari", "edge"]:
        config = getattr(BrowserFingerprints, {
            "chrome": "chrome_desktop",
            "firefox": "firefox_desktop",
            "safari": "safari",
            "edge": "edge",
        }[browser])()
        generator = TLSFingerprintGenerator()
        generator.set_config(config)
        client_hello = generator.generate_client_hello("example.com")
        assert len(client_hello) > 0, f"{browser} ClientHello 为空"
        raw = bytes(client_hello) if isinstance(client_hello, list) else client_hello
        print(f"    [{browser:>8}] ClientHello: {len(client_hello)} bytes, "
              f"starts with: {raw[:8].hex()}")


@run_test("17. TLSFingerprintAnalyzer 指纹分析")
def test_fingerprint_analyzer(proxy=None, debug=False):
    """USAGE.md - TLSFingerprintAnalyzer.identify_browser (静态方法)"""
    configs = {
        "Chrome": BrowserFingerprints.chrome_desktop(),
        "Firefox": BrowserFingerprints.firefox_desktop(),
        "Safari": BrowserFingerprints.safari(),
    }

    for expected, config in configs.items():
        identified = TLSFingerprintAnalyzer.identify_browser(config)
        print(f"    {expected} -> identified as: {identified}")
        assert identified != "Unknown", f"未能识别 {expected}: got {identified}"


@run_test("18. 动态切换代理")
def test_dynamic_proxy_switch(proxy=None, debug=False):
    """USAGE.md - 动态切换代理 (set_proxy / clear_proxy)"""
    client = TLSHttpClient(browser_type="chrome", debug=debug)

    if proxy:
        client.set_proxy(proxy)
        r1 = client.get(IP_URL)
        print(f"    通过代理: status={r1.status_code}, ip={r1.text.strip()}")

    client.clear_proxy()
    r2 = client.get(IP_URL)
    print(f"    直连: status={r2.status_code}, ip={r2.text.strip()}")
    assert r2.status_code == 200


@run_test("19. 多账户多指纹模拟")
def test_multi_account(proxy=None, debug=False):
    """USAGE.md - 多账户多指纹"""
    accounts = {}
    for user in ["user1", "user2", "user3"]:
        session = TLSSession(browser_type="random")
        accounts[user] = {
            "client": TLSHttpClient(session=session, proxy=proxy, debug=debug),
            "session": session,
        }
        print(f"    {user}: browser={session.browser_type}, session={session.session_id[:8]}...")

    # 每个账户发送请求
    for user, info in accounts.items():
        response = retry(lambda c=info["client"]: c.get(IP_URL))
        assert response.status_code == 200, f"{user} 请求失败"
        print(f"    {user} 请求成功: {response.text.strip()}")


@run_test("20. 超时设置")
def test_timeout(proxy=None, debug=False):
    """USAGE.md - timeout 参数"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, timeout=10.0, debug=debug)
    response = client.get(IP_URL)
    assert response.status_code == 200
    print(f"    timeout=10s, status={response.status_code}")


@run_test("21. 默认请求头")
def test_default_headers(proxy=None, debug=False):
    """USAGE.md - default_headers 参数"""
    client = TLSHttpClient(
        browser_type="chrome",
        proxy=proxy,
        debug=debug,
        default_headers={
            "Referer": "https://www.google.com/",
            "X-Custom-Header": "test-value",
        },
    )
    response = client.get(HEADERS_URL)
    assert response.status_code == 200
    data = response.json()
    headers = data.get("headers", {})
    print(f"    Referer: {headers.get('Referer', 'N/A')}")
    print(f"    X-Custom-Header: {headers.get('X-Custom-Header', 'N/A')}")


@run_test("22. PUT / DELETE / HEAD 请求方法")
def test_other_methods(proxy=None, debug=False):
    """USAGE.md - put / delete / head 方法"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)

    # PUT
    r1 = client.put(
        "https://httpbin.org/put",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"action": "update"}).encode()
    )
    assert r1.status_code == 200, f"PUT 失败: {r1.status_code}"
    print(f"    PUT: status={r1.status_code}")

    # DELETE
    r2 = client.delete("https://httpbin.org/delete")
    assert r2.status_code == 200, f"DELETE 失败: {r2.status_code}"
    print(f"    DELETE: status={r2.status_code}")

    # HEAD
    r3 = client.head(GET_URL)
    assert r3.status_code == 200, f"HEAD 失败: {r3.status_code}"
    print(f"    HEAD: status={r3.status_code}, body_len={len(r3.body)}")


@run_test("23. 通用 request() 方法")
def test_generic_request(proxy=None, debug=False):
    """USAGE.md - request(method, url, ...) 通用接口"""
    client = TLSHttpClient(browser_type="chrome", proxy=proxy, debug=debug)
    response = client.request("GET", GET_URL)
    assert response.status_code == 200
    print(f"    request('GET'): status={response.status_code}")

    response2 = client.request(
        "POST", POST_URL,
        headers={"Content-Type": "application/json"},
        body=json.dumps({"via": "request()"}).encode()
    )
    assert response2.status_code == 200
    print(f"    request('POST'): status={response2.status_code}")


@run_test("24. TLS 指纹验证 (tls.peet.ws)")
def test_tls_fingerprint_verify(proxy=None, debug=False):
    """访问 tls.peet.ws 验证 TLS 指纹特征"""
    for browser in ["chrome", "firefox"]:
        client = TLSHttpClient(browser_type=browser, proxy=proxy, debug=debug)
        try:
            response = client.get(TLS_URL)
            if response.status_code == 200:
                data = response.json()
                ja4 = data.get("ja4", "N/A")
                ja3 = data.get("ja3_hash", data.get("ja3", "N/A"))
                h2 = data.get("h2", {})
                print(f"    [{browser:>8}] JA4={ja4}, JA3={str(ja3)[:32]}...")
                if h2:
                    print(f"    [{browser:>8}] H2 fingerprint available")
            else:
                print(f"    [{browser:>8}] status={response.status_code} (non-200, skipping)")
        except Exception as e:
            print(f"    [{browser:>8}] tls.peet.ws 不可达, 跳过: {e}")


# ───────────────────────────────────────
# 测试运行器
# ───────────────────────────────────────

ALL_TESTS = [
    ("basic",       test_basic_get),
    ("post_json",   test_post_json),
    ("post_form",   test_post_form),
    ("browsers",    test_browser_fingerprints),
    ("random",      test_random_fingerprint),
    ("session",     test_session_consistency),
    ("multi_sess",  test_multi_session),
    ("pool",        test_fingerprint_pool),
    ("response",    test_response_fields),
    ("proxy_cfg",   test_proxy_config),
    ("presets",     test_browser_presets),
    ("custom_cfg",  test_custom_config),
    ("modify_cfg",  test_modify_preset),
    ("convenience", test_convenience_functions),
    ("create_sess", test_create_session_helpers),
    ("clienthello", test_client_hello_generator),
    ("analyzer",    test_fingerprint_analyzer),
    ("proxy_switch", test_dynamic_proxy_switch),
    ("multi_acct",  test_multi_account),
    ("timeout",     test_timeout),
    ("headers",     test_default_headers),
    ("methods",     test_other_methods),
    ("request",     test_generic_request),
    ("tls_verify",  test_tls_fingerprint_verify),
]


def run_single(test_fn, proxy=None, debug=False):
    name = test_fn._test_name
    print(f"\n{'=' * 65}")
    print(f"  {name}")
    print(f"{'=' * 65}")
    start = time.time()
    try:
        test_fn(proxy=proxy, debug=debug)
        elapsed = time.time() - start
        result.add(name, True, elapsed)
    except Exception as e:
        elapsed = time.time() - start
        result.add(name, False, elapsed, str(e))
        print(f"    FAIL: {e}")
        traceback.print_exc()


def run_all(proxy=None, debug=False):
    print("=" * 65)
    print(f"  TLS Fingerprint 全功能测试")
    print(f"  Proxy: {proxy or '直连'}")
    print(f"  Debug: {debug}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    for i, (_, test_fn) in enumerate(ALL_TESTS):
        if i > 0:
            time.sleep(INTER_TEST_DELAY)
        run_single(test_fn, proxy=proxy, debug=debug)

    return result.summary()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Fingerprint 全功能测试脚本")
    parser.add_argument("--proxy", type=str, default=None,
                        help="代理地址, 如 http://127.0.0.1:7897 或 socks5://127.0.0.1:1080")
    parser.add_argument("--debug", action="store_true",
                        help="开启调试日志")
    parser.add_argument("--test", type=str, default=None,
                        help="运行单个测试 (使用 --list 查看所有测试名)")
    parser.add_argument("--list", action="store_true",
                        help="列出所有测试项")
    args = parser.parse_args()

    if args.list:
        print("可用测试项:")
        for key, fn in ALL_TESTS:
            print(f"  {key:>14}  ->  {fn._test_name}")
        sys.exit(0)

    if args.test:
        found = False
        for key, fn in ALL_TESTS:
            if key == args.test:
                run_single(fn, proxy=args.proxy, debug=args.debug)
                result.summary()
                found = True
                break
        if not found:
            print(f"未知测试: {args.test}")
            print(f"可选: {', '.join(k for k, _ in ALL_TESTS)}")
            sys.exit(1)
    else:
        success = run_all(proxy=args.proxy, debug=args.debug)
        sys.exit(0 if success else 1)
