"""
TLS 指纹检测脚本
通过 https://tls.browserleaks.com/json 检测实际 TLS 指纹信息
"""
import time
import json
from tls_fingerprint import (
    TLSHttpClient,
    TLSFingerprintPool,
    TLSSession,
)

BROWSER_TYPES = ["chrome", "firefox", "safari", "edge"]
TEST_URL = "https://tls.browserleaks.com/json"

# 强制不压缩，避免 brotli 解压失败导致乱码
NO_COMPRESS_HEADERS = {"Accept-Encoding": "identity"}


def safe_json(response):
    """安全解析 JSON，失败时打印原始响应"""
    try:
        return response.json()
    except Exception:
        text = response.text
        if not text or not text.strip():
            print(f"  ⚠️ 响应体为空 (status={response.status_code}, body_len={len(response.body)})")
        else:
            print(f"  ⚠️ JSON 解析失败，原始响应:")
            print(f"     {text[:500]}")
        return None


def print_fingerprint(data, prefix="  "):
    """打印完整指纹信息"""
    fields = [
        ("user_agent",   "User-Agent"),
        ("ja4",          "JA4"),
        ("ja4_r",        "JA4-R"),
        ("ja4_o",        "JA4-O"),
        ("ja4_ro",       "JA4-RO"),
        ("ja3_hash",     "JA3 Hash"),
        ("ja3_text",     "JA3 Text"),
        ("ja3n_hash",    "JA3N Hash"),
        ("ja3n_text",    "JA3N Text"),
        ("akamai_hash",  "Akamai Hash"),
        ("akamai_text",  "Akamai Text"),
    ]
    for key, label in fields:
        val = data.get(key)
        if val:
            print(f"{prefix}{label:<14} {val}")


def test_single(browser_type):
    """单个浏览器指纹检测"""
    print(f"\n{'=' * 70}")
    print(f"  浏览器: {browser_type}")
    print(f"{'=' * 70}")

    session = TLSSession(browser_type=browser_type)
    client = TLSHttpClient(session=session, default_headers=NO_COMPRESS_HEADERS)

    print(f"  Session: {session.session_id[:16]}...")
    print(f"  JA3:     {session.get_ja3_hash()}")

    response = client.get(TEST_URL)
    if response.status_code != 200:
        print(f"  ❌ 请求失败: {response.status_code}")
        return None

    data = safe_json(response)
    if not data:
        return None
    print(f"\n  --- 服务端检测到的 TLS 指纹 ---")
    print_fingerprint(data)
    return data


def test_pool(pool_size=10):
    """指纹池批量检测"""
    print(f"\n{'=' * 70}")
    print(f"  指纹池检测 (size={pool_size})")
    print(f"{'=' * 70}")

    pool = TLSFingerprintPool(pool_size=pool_size, browser_types=BROWSER_TYPES)
    print(f"  Pool size: {len(pool)}\n")

    ja3_set = set()
    results = []

    for i in range(pool_size):
        session = pool.get_next()
        client = TLSHttpClient(session=session, default_headers=NO_COMPRESS_HEADERS)

        try:
            response = client.get(TEST_URL)
            if response.status_code != 200:
                print(f"  [{i:>2}] ❌ status={response.status_code}")
                continue

            data = safe_json(response)
            if not data:
                continue
            ja3 = data.get('ja3_hash', 'N/A')
            ja3_set.add(ja3)
            results.append({
                "index": i,
                "browser": session.browser_type,
                "data": data,
            })
            print(f"\n  [{i:>2}] browser={session.browser_type}")
            print_fingerprint(data, prefix="       ")

        except Exception as e:
            print(f"  [{i:>2}] ❌ {e}")

    # 汇总
    print(f"\n  --- 汇总 ---")
    print(f"  总请求数: {len(results)}")
    print(f"  唯一 JA3: {len(ja3_set)}")

    # 按浏览器分组统计
    browser_ja3 = {}
    for r in results:
        bt = r["browser"]
        if bt not in browser_ja3:
            browser_ja3[bt] = set()
        browser_ja3[bt].add(r["data"].get('ja3_hash', 'N/A'))

    print(f"\n  按浏览器分组:")
    for bt, ja3s in browser_ja3.items():
        print(f"    {bt:>12}: {len(ja3s)} 个唯一 JA3")
        for j in ja3s:
            print(f"                  {j}")

    return results


def test_session_stability():
    """同一会话多次请求，验证指纹一致性"""
    print(f"\n{'=' * 70}")
    print(f"  会话稳定性测试 (同一会话请求 3 次)")
    print(f"{'=' * 70}")

    session = TLSSession(browser_type="random")
    client = TLSHttpClient(session=session, default_headers=NO_COMPRESS_HEADERS)
    print(f"  Session: {session.session_id[:16]}...")
    print(f"  Browser: {session.browser_type}")

    ja3_list = []
    for i in range(3):
        response = client.get(TEST_URL)
        if response.status_code != 200:
            print(f"  [{i}] ❌ status={response.status_code}")
            continue
        data = safe_json(response)
        if not data:
            continue
        ja3 = data.get('ja3_hash', 'N/A')
        ja3_list.append(ja3)
        print(f"\n  [{i}]")
        print_fingerprint(data, prefix="    ")

    if len(set(ja3_list)) == 1:
        print(f"  ✅ 3 次请求 JA3 一致: {ja3_list[0]}")
    else:
        print(f"  ❌ JA3 不一致: {ja3_list}")


if __name__ == "__main__":
    print("=" * 70)
    print("  TLS 指纹检测  |  https://tls.browserleaks.com/json")
    print(f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # 1. 单浏览器逐个测试
    print("\n\n>>> 第一部分: 单浏览器指纹检测")
    for bt in BROWSER_TYPES:
        test_single(bt)
        time.sleep(0.5)

    # 2. 指纹池批量测试
    print("\n\n>>> 第二部分: 指纹池批量检测")
    test_pool(10)

    # 3. 会话稳定性
    print("\n\n>>> 第三部分: 会话稳定性")
    test_session_stability()

    print("\n\n全部检测完成 ✅")
