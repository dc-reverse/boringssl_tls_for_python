"""
Pure Python implementation of TLS Fingerprint Library.
This module provides fallback functionality when the C extension is not available.
"""

import hashlib
import random
import time
import struct
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


# TLS version constants
SSL_PROTOCOL_VERSION_TLS1_2 = 0x0303
SSL_PROTOCOL_VERSION_TLS1_3 = 0x0304

# Cipher suite constants
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8
# Legacy cipher suites
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035

# Signature algorithm constants
ECDSA_SECP256R1_SHA256 = 0x0403
RSA_PSS_RSAE_SHA256 = 0x0804
RSA_PKCS1_SHA256 = 0x0401
ECDSA_SECP384R1_SHA384 = 0x0503
RSA_PSS_RSAE_SHA384 = 0x0805
RSA_PSS_RSAE_SHA512 = 0x0806

# Named group constants
X25519 = 0x001D
SECP256R1 = 0x0017
SECP384R1 = 0x0018
SECP521R1 = 0x0019


@dataclass
class TLSFingerprintConfig:
    """TLS fingerprint configuration."""
    version_min: int = SSL_PROTOCOL_VERSION_TLS1_2
    version_max: int = SSL_PROTOCOL_VERSION_TLS1_3
    cipher_suites: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    named_groups: List[int] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    permute_extensions: bool = True
    enable_grease: bool = True
    enable_ech: bool = False
    ech_config_list: bytes = b""
    custom_extensions: Dict[int, bytes] = field(default_factory=dict)


class BrowserFingerprints:
    """Browser fingerprint presets based on real browser TLS fingerprints."""

    @staticmethod
    def chrome_desktop() -> TLSFingerprintConfig:
        """Get Chrome desktop browser fingerprint (Chrome 131+)."""
        config = TLSFingerprintConfig()
        config.cipher_suites = [
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            # Legacy cipher suites
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
        ]
        # Chrome signature algorithms (only algorithms supported by BoringSSL)
        # Note: BoringSSL doesn't support brainpool curves, ed448, RSA-PSS-PSS, or DSA
        config.signature_algorithms = [
            0x0403,  # ecdsa_secp256r1_sha256
            0x0503,  # ecdsa_secp384r1_sha384
            0x0603,  # ecdsa_secp521r1_sha512
            0x0804,  # rsa_pss_rsae_sha256
            0x0805,  # rsa_pss_rsae_sha384
            0x0806,  # rsa_pss_rsae_sha512
            0x0401,  # rsa_pkcs1_sha256
            0x0501,  # rsa_pkcs1_sha384
            0x0601,  # rsa_pkcs1_sha512
            0x0201,  # rsa_pkcs1_sha1 (legacy)
            0x0203,  # ecdsa_sha1 (legacy)
            0x0807,  # ed25519
            0x0420,  # rsa_pkcs1_sha256_legacy
        ]
        # Chrome named groups (all groups supported by BoringSSL)
        # Includes post-quantum groups for TLS 1.3
        config.named_groups = [
            0x11ec,  # x25519_mlkem768 (4588) - post-quantum
            0x001D,  # x25519 (29)
            0x0017,  # secp256r1 (23)
            0x0018,  # secp384r1 (24)
            0x0019,  # secp521r1 (25)
        ]
        config.alpn_protocols = ["h2", "http/1.1"]
        config.permute_extensions = True
        config.enable_grease = True
        return config

    @staticmethod
    def chrome_android() -> TLSFingerprintConfig:
        """Chrome Android - same as desktop."""
        return BrowserFingerprints.chrome_desktop()

    @staticmethod
    def firefox_desktop() -> TLSFingerprintConfig:
        """Get Firefox desktop browser fingerprint (Firefox 121+)."""
        config = TLSFingerprintConfig()
        config.cipher_suites = [
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            # Legacy cipher suites
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
        ]
        # Firefox signature algorithms (only BoringSSL-supported algorithms)
        config.signature_algorithms = [
            0x0403,  # ecdsa_secp256r1_sha256
            0x0503,  # ecdsa_secp384r1_sha384
            0x0603,  # ecdsa_secp521r1_sha512
            0x0804,  # rsa_pss_rsae_sha256
            0x0805,  # rsa_pss_rsae_sha384
            0x0806,  # rsa_pss_rsae_sha512
            0x0401,  # rsa_pkcs1_sha256
            0x0501,  # rsa_pkcs1_sha384
            0x0601,  # rsa_pkcs1_sha512
            0x0807,  # ed25519
            0x0201,  # rsa_pkcs1_sha1
        ]
        # Firefox named groups (BoringSSL-supported only, no ffdhe)
        config.named_groups = [
            0x001D,  # x25519
            0x0017,  # secp256r1
            0x0018,  # secp384r1
        ]
        config.alpn_protocols = ["h2", "http/1.1"]
        config.permute_extensions = False
        config.enable_grease = False
        return config

    @staticmethod
    def safari() -> TLSFingerprintConfig:
        """Get Safari browser fingerprint (Safari 17+)."""
        config = TLSFingerprintConfig()
        # Safari cipher suites - Real Safari order: 4866-4867-4865-49195-49199-49196-49200
        # Has TLS 1.3 CHACHA20 (4867), but NO TLS 1.2 CHACHA20 (52393/52392)
        config.cipher_suites = [
            TLS_AES_256_GCM_SHA384,      # 4866 - Safari puts AES256 first
            TLS_CHACHA20_POLY1305_SHA256, # 4867 - TLS 1.3 CHACHA20 is OK
            TLS_AES_128_GCM_SHA256,       # 4865
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  # 49195
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    # 49199
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  # 49196
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,    # 49200
            # NO 0xCCA9/0xCCA8 (TLS 1.2 CHACHA20) - Safari doesn't support
        ]
        # Safari signature algorithms (only BoringSSL-supported algorithms)
        config.signature_algorithms = [
            0x0403,  # ecdsa_secp256r1_sha256
            0x0503,  # ecdsa_secp384r1_sha384
            0x0603,  # ecdsa_secp521r1_sha512
            0x0804,  # rsa_pss_rsae_sha256
            0x0805,  # rsa_pss_rsae_sha384
            0x0806,  # rsa_pss_rsae_sha512
            0x0401,  # rsa_pkcs1_sha256
            0x0501,  # rsa_pkcs1_sha384
            0x0601,  # rsa_pkcs1_sha512
            0x0807,  # ed25519
            0x0201,  # rsa_pkcs1_sha1
        ]
        # Safari named groups (only BoringSSL-supported groups)
        config.named_groups = [
            0x001D,  # x25519
            0x0017,  # secp256r1
            0x0018,  # secp384r1
            0x0019,  # secp521r1
        ]
        config.alpn_protocols = ["h2", "http/1.1"]
        config.permute_extensions = False
        config.enable_grease = True
        return config

    @staticmethod
    def edge() -> TLSFingerprintConfig:
        """Edge is based on Chromium, same as Chrome."""
        return BrowserFingerprints.chrome_desktop()


# GREASE values
_GREASE_VALUES = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
                  0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
                  0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA]

# Extension types
EXT_SERVER_NAME = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SCT = 0x0012
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_COMPRESS_CERTIFICATE = 0x001B
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
EXT_APPLICATION_SETTINGS = 0x4469
EXT_RENEGOTIATION_INFO = 0xFF01


class TLSFingerprintGenerator:
    """Generate TLS ClientHello with custom fingerprint."""

    def __init__(self):
        self._config: Optional[TLSFingerprintConfig] = None
        self._rng = random.Random(time.time_ns())

    def set_config(self, config: TLSFingerprintConfig) -> None:
        self._config = config

    def get_config(self) -> Optional[TLSFingerprintConfig]:
        return self._config

    def generate_client_hello(self, hostname: str) -> bytes:
        if self._config is None:
            self._config = BrowserFingerprints.chrome_desktop()

        return self._build_client_hello(hostname)

    def _build_client_hello(self, hostname: str) -> bytes:
        # Build ClientHello body
        body = bytearray()

        # Client version (legacy, use TLS 1.2 for compatibility)
        body.extend([0x03, 0x03])

        # Random (32 bytes)
        body.extend(self._rng.randbytes(32))

        # Session ID (empty for TLS 1.3)
        body.append(0x00)

        # Cipher suites
        self._write_u16(body, len(self._config.cipher_suites) * 2)
        for cs in self._config.cipher_suites:
            self._write_u16(body, cs)

        # Compression methods
        body.extend([0x01, 0x00])  # null compression only

        # Extensions
        extensions = self._build_extensions(hostname)
        self._write_u16(body, len(extensions))
        body.extend(extensions)

        # Build handshake message
        handshake = bytearray()
        handshake.append(0x01)  # ClientHello type
        self._write_u24(handshake, len(body))
        handshake.extend(body)

        # Build TLS record
        record = bytearray()
        record.append(0x16)  # Handshake
        record.extend([0x03, 0x01])  # TLS 1.0 record layer version
        self._write_u16(record, len(handshake))
        record.extend(handshake)

        return bytes(record)

    def _build_extensions(self, hostname: str) -> bytes:
        ext_list = []

        # Server Name Indication
        sni = bytearray()
        self._write_u16(sni, len(hostname) + 3)
        sni.append(0x00)  # host name type
        self._write_u16(sni, len(hostname))
        sni.extend(hostname.encode())
        ext_list.append((EXT_SERVER_NAME, bytes(sni)))

        # Extended Master Secret
        ext_list.append((EXT_EXTENDED_MASTER_SECRET, b""))

        # Renegotiation Info
        ext_list.append((EXT_RENEGOTIATION_INFO, b"\x00"))

        # Supported Groups
        groups = bytearray()
        self._write_u16(groups, len(self._config.named_groups) * 2)
        for g in self._config.named_groups:
            self._write_u16(groups, g)
        ext_list.append((EXT_SUPPORTED_GROUPS, bytes(groups)))

        # EC Point Formats (Chrome sends uncompressed only)
        ec_pf = bytearray([0x01, 0x00])  # length=1, uncompressed=0
        ext_list.append((EXT_EC_POINT_FORMATS, bytes(ec_pf)))

        # Signature Algorithms
        sig_algs = bytearray()
        self._write_u16(sig_algs, len(self._config.signature_algorithms) * 2)
        for sa in self._config.signature_algorithms:
            self._write_u16(sig_algs, sa)
        ext_list.append((EXT_SIGNATURE_ALGORITHMS, bytes(sig_algs)))

        # ALPN
        alpn = bytearray()
        proto_list = bytearray()
        for proto in self._config.alpn_protocols:
            proto_list.append(len(proto))
            proto_list.extend(proto.encode())
        self._write_u16(alpn, len(proto_list))
        alpn.extend(proto_list)
        ext_list.append((EXT_ALPN, bytes(alpn)))

        # Status Request (OCSP stapling)
        ocsp = bytearray([0x01, 0x00, 0x00, 0x00, 0x00])
        ext_list.append((EXT_STATUS_REQUEST, bytes(ocsp)))

        # Signed Certificate Timestamp
        ext_list.append((EXT_SCT, b""))

        # Session Ticket (empty)
        ext_list.append((EXT_SESSION_TICKET, b""))

        # Compress Certificate (Brotli = algorithm 2)
        compress = bytearray([0x02, 0x00, 0x02])  # length=2, brotli=0x0002
        ext_list.append((EXT_COMPRESS_CERTIFICATE, bytes(compress)))

        # Application Settings (ALPS) for HTTP/2
        alps = bytearray()
        alps_proto = b"h2"
        alps_list = bytearray()
        alps_list.append(len(alps_proto))
        alps_list.extend(alps_proto)
        self._write_u16(alps, len(alps_list))
        alps.extend(alps_list)
        ext_list.append((EXT_APPLICATION_SETTINGS, bytes(alps)))

        # Supported Versions - TLS 1.3 first (preferred), then TLS 1.2
        versions = bytearray([0x04])  # 4 bytes = 2 versions
        versions.extend([0x03, 0x04])  # TLS 1.3
        versions.extend([0x03, 0x03])  # TLS 1.2
        ext_list.append((EXT_SUPPORTED_VERSIONS, bytes(versions)))

        # Key Share - Chrome only sends shares for x25519_mlkem768 + x25519
        key_share = bytearray()
        key_entries = bytearray()
        for group in self._config.named_groups:
            # Skip NIST curves in key share (Chrome doesn't send these)
            if group in (SECP256R1, SECP384R1, SECP521R1):
                continue

            share_entry = bytearray()
            self._write_u16(share_entry, group)

            key_size = 32  # x25519
            if group == 0x11EC:  # x25519_mlkem768
                key_size = 1120

            self._write_u16(share_entry, key_size)
            share_entry.extend(self._rng.randbytes(key_size))
            key_entries.extend(share_entry)

        self._write_u16(key_share, len(key_entries))
        key_share.extend(key_entries)
        ext_list.append((EXT_KEY_SHARE, bytes(key_share)))

        # PSK Key Exchange Modes - Chrome only sends psk_dhe_ke (1)
        psk_modes = bytearray([0x01, 0x01])  # length=1, psk_dhe_ke=1
        ext_list.append((EXT_PSK_KEY_EXCHANGE_MODES, bytes(psk_modes)))

        # GREASE extensions (Chrome adds 2 GREASE extensions)
        if self._config.enable_grease:
            grease1 = self._rng.choice(_GREASE_VALUES)
            ext_list.insert(0, (grease1, b"\x00"))

            grease2 = self._rng.choice(_GREASE_VALUES)
            while grease2 == grease1:
                grease2 = self._rng.choice(_GREASE_VALUES)
            ext_list.append((grease2, b"\x00"))

        # Permute extensions (Chrome randomizes since v110)
        if self._config.permute_extensions:
            self._rng.shuffle(ext_list)

        # Serialize extensions
        result = bytearray()
        for ext_type, ext_data in ext_list:
            self._write_u16(result, ext_type)
            self._write_u16(result, len(ext_data))
            result.extend(ext_data)

        return bytes(result)

    def _write_u16(self, buf: bytearray, val: int) -> None:
        buf.append((val >> 8) & 0xFF)
        buf.append(val & 0xFF)

    def _write_u24(self, buf: bytearray, val: int) -> None:
        buf.append((val >> 16) & 0xFF)
        buf.append((val >> 8) & 0xFF)
        buf.append(val & 0xFF)


class TLSFingerprintAnalyzer:
    """Analyze TLS fingerprints."""

    @staticmethod
    def identify_browser(config: TLSFingerprintConfig) -> str:
        chrome = BrowserFingerprints.chrome_desktop()
        if config.cipher_suites == chrome.cipher_suites:
            return "Chrome"

        firefox = BrowserFingerprints.firefox_desktop()
        if config.cipher_suites == firefox.cipher_suites:
            return "Firefox"

        safari = BrowserFingerprints.safari()
        if config.cipher_suites == safari.cipher_suites:
            return "Safari"

        return "Unknown"

    @staticmethod
    def parse_client_hello(data: bytes) -> TLSFingerprintConfig:
        # Basic parsing - could be expanded
        return TLSFingerprintConfig()


# Utility functions
_CIPHER_SUITE_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

_SIG_ALG_NAMES = {
    0x0403: "ECDSA_SECP256R1_SHA256",
    0x0804: "RSA_PSS_RSAE_SHA256",
    0x0401: "RSA_PKCS1_SHA256",
    0x0503: "ECDSA_SECP384R1_SHA384",
    0x0805: "RSA_PSS_RSAE_SHA384",
    0x0806: "RSA_PSS_RSAE_SHA512",
}

_GROUP_NAMES = {
    0x11EC: "x25519_mlkem768",
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
}


def get_cipher_suite_name(cipher_suite: int) -> str:
    return _CIPHER_SUITE_NAMES.get(cipher_suite, "UNKNOWN")


def get_cipher_suite_version(cipher_suite: int) -> str:
    if 0x1301 <= cipher_suite <= 0x1303:
        return "TLS 1.3"
    return "TLS 1.2"


def get_signature_algorithm_name(sig_alg: int) -> str:
    return _SIG_ALG_NAMES.get(sig_alg, "UNKNOWN")


def get_named_group_name(named_group: int) -> str:
    return _GROUP_NAMES.get(named_group, "UNKNOWN")
