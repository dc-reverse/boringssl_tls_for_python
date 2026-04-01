# TLS Fingerprint Library - Python Bindings
"""
Chromium-based TLS fingerprint library for Python.

This library provides TLS fingerprint configuration functionality extracted from Chromium,
allowing Python applications to mimic browser TLS fingerprints.

Quick Start:
    from tls_fingerprint import TLSSession, TLSHttpClient

    # Create a session with random fingerprint
    session = TLSSession(browser_type="random")
    # Generate ClientHello
    client_hello = session.generate_client_hello("example.com")
    # Or use TLSHttpClient for HTTP requests with proxy support
    client = TLSHttpClient(browser_type="chrome", proxy="http://127.0.0.1:7897")
    response = client.get("https://example.com")
"""

import sys
import os

__version__ = "1.0.0"
__author__ = "TLS Fingerprint Team"

# Try to import C extension, fall back to pure Python
_use_native = False
_native_module = None

def _try_load_native():
    """Try to load the native C extension."""
    global _native_module, _use_native
    if _native_module is not None:
        return _native_module

    try:
        from . import _tls_fingerprint as _native
        _native_module = _native
        _use_native = True
        return _native_module
    except ImportError:
        # C extension not available, will use pure Python
        return None
    except Exception:
        # Any other error (like GIL issues), use pure Python
        return None

# Load native module at import time
_native = _try_load_native()

# Import core classes - prefer native, fallback to pure Python
if _native:
    TLSFingerprintConfig = _native.TLSFingerprintConfig
    TLSFingerprintGenerator = _native.TLSFingerprintGenerator
    BrowserFingerprints = _native.BrowserFingerprints
    BoringSSLSocket = _native.BoringSSLSocket
    SSLConnectionInfo = _native.SSLConnectionInfo

    # Constants from native
    TLS_AES_128_GCM_SHA256 = _native.TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384 = _native.TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256 = _native.TLS_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = _native.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = _native.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ECDSA_SECP256R1_SHA256 = _native.ECDSA_SECP256R1_SHA256
    RSA_PSS_RSAE_SHA256 = _native.RSA_PSS_RSAE_SHA256
    X25519 = _native.X25519
    SECP256R1 = _native.SECP256R1
    SECP384R1 = _native.SECP384R1
else:
    # Pure Python fallback
    from .pure_python import (
        TLSFingerprintConfig,
        TLSFingerprintGenerator,
        BrowserFingerprints,
        # Constants
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ECDSA_SECP256R1_SHA256,
        RSA_PSS_RSAE_SHA256,
        X25519,
        SECP256R1,
        SECP384R1,
    )

    # BoringSSLSocket not available without native module
    class BoringSSLSocket:
        def __init__(self):
            raise ImportError("BoringSSLSocket requires native BoringSSL extension")

    class SSLConnectionInfo:
        def __init__(self):
            raise ImportError("SSLConnectionInfo requires native BoringSSL extension")

# Import high-level Python modules
from .session import (
    TLSSession,
    TLSClient,
    TLSFingerprintPool,
    FingerprintInfo,
    create_session,
    create_random_session,
    generate_client_hello,
)

from .client import (
    TLSHttpClient,
    ProxyConfig,
    HttpResponse,
    get as http_get,
    post as http_post,
)

# Utility functions - use native if available, otherwise pure Python
def get_cipher_suite_name(cipher_suite: int) -> str:
    """Get human-readable name for cipher suite ID."""
    if _native:
        return _native.get_cipher_suite_name(cipher_suite)
    from .pure_python import get_cipher_suite_name as _get_name
    return _get_name(cipher_suite)

def get_cipher_suite_version(cipher_suite: int) -> str:
    """Get TLS version for cipher suite."""
    if _native:
        return _native.get_cipher_suite_version(cipher_suite)
    from .pure_python import get_cipher_suite_version as _get_version
    return _get_version(cipher_suite)

def get_signature_algorithm_name(sig_alg: int) -> str:
    """Get human-readable name for signature algorithm ID."""
    if _native:
        return _native.get_signature_algorithm_name(sig_alg)
    from .pure_python import get_signature_algorithm_name as _get_name
    return _get_name(sig_alg)

def get_named_group_name(named_group: int) -> str:
    """Get human-readable name for named group ID."""
    if _native:
        return _native.get_named_group_name(named_group)
    from .pure_python import get_named_group_name as _get_name
    return _get_name(named_group)

# TLSFingerprintAnalyzer - wrapper for native or pure Python
class TLSFingerprintAnalyzer:
    """TLS fingerprint analyzer (wrapper for native or pure Python)."""

    @staticmethod
    def identify_browser(config):
        """Identify browser type from fingerprint configuration."""
        if _native and hasattr(_native, 'TLSFingerprintAnalyzer'):
            return _native.TLSFingerprintAnalyzer.identify_browser(config)
        # Pure Python fallback
        from .pure_python import TLSFingerprintAnalyzer as _Analyzer
        return _Analyzer.identify_browser(config)

    @staticmethod
    def parse_client_hello(client_hello):
        """Parse ClientHello bytes and extract configuration."""
        if _native and hasattr(_native, 'TLSFingerprintAnalyzer'):
            return _native.TLSFingerprintAnalyzer.parse_client_hello(client_hello)
        # Pure Python fallback
        from .pure_python import TLSFingerprintAnalyzer as _Analyzer
        return _Analyzer.parse_client_hello(client_hello)

    def __repr__(self):
        return "<TLSFingerprintAnalyzer>"

__all__ = [
    # Core classes
    "TLSFingerprintConfig",
    "TLSFingerprintGenerator",
    "TLSFingerprintAnalyzer",
    "BrowserFingerprints",
    # BoringSSL Socket
    "BoringSSLSocket",
    "SSLConnectionInfo",
    # High-level API
    "TLSSession",
    "TLSClient",
    "TLSFingerprintPool",
    "FingerprintInfo",
    # Convenience functions
    "create_session",
    "create_random_session",
    "generate_client_hello",
    # HTTP Client
    "TLSHttpClient",
    "ProxyConfig",
    "HttpResponse",
    "http_get",
    "http_post",
    # Utility functions
    "get_cipher_suite_name",
    "get_cipher_suite_version",
    "get_signature_algorithm_name",
    "get_named_group_name",
    # Constants
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDSA_SECP256R1_SHA256",
    "RSA_PSS_RSAE_SHA256",
    "X25519",
    "SECP256R1",
    "SECP384R1",
]
