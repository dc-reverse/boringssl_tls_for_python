"""
HTTP/2 Fingerprinting Configuration and Implementation.

This module provides HTTP/2 fingerprinting support to complement TLS fingerprinting.
Modern bot detection systems (Akamai, Cloudflare) use HTTP/2 SETTINGS frame,
WINDOW_UPDATE values, and pseudo-header ordering to detect bots.

Reference: https://ijazurrahim.com/blog/fingerprinting-beyond-ja3.html
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntEnum


class HTTP2Setting(IntEnum):
    """HTTP/2 SETTINGS frame parameters."""
    HEADER_TABLE_SIZE = 0x1
    ENABLE_PUSH = 0x2
    MAX_CONCURRENT_STREAMS = 0x3
    INITIAL_WINDOW_SIZE = 0x4
    MAX_FRAME_SIZE = 0x5
    MAX_HEADER_LIST_SIZE = 0x6
    UNKNOWN_SETTING_8 = 0x8  # Used by Chrome 130+


@dataclass
class HTTP2FingerprintConfig:
    """
    HTTP/2 fingerprint configuration for a specific browser.

    This configuration matches the HTTP/2 behavior of real browsers
    to pass Akamai and Cloudflare HTTP/2 fingerprinting.
    """
    # SETTINGS frame parameters (in order they appear)
    settings: List[Tuple[int, int]] = field(default_factory=list)

    # WINDOW_UPDATE value sent after SETTINGS
    window_update_increment: int = 15663105

    # Pseudo-header order: method, authority, scheme, path
    # Different browsers use different orders
    pseudo_header_order: List[str] = field(default_factory=lambda: [":method", ":authority", ":scheme", ":path"])

    # Header order for common headers (after pseudo-headers)
    header_order: List[str] = field(default_factory=list)

    # Priority frame settings
    enable_priority: bool = True
    priority_stream_id: int = 3
    priority_weight: int = 200

    # Connection preface settings
    client_preface: str = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def get_settings_dict(self) -> Dict[int, int]:
        """Get settings as dictionary."""
        return {k: v for k, v in self.settings}

    def get_settings_order(self) -> List[int]:
        """Get settings IDs in order."""
        return [k for k, v in self.settings]


class HTTP2BrowserFingerprints:
    """HTTP/2 fingerprint presets for different browsers."""

    @staticmethod
    def chrome() -> HTTP2FingerprintConfig:
        """
        Chrome HTTP/2 fingerprint (Chrome 120+).

        Chrome's HTTP/2 fingerprint:
        - SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000,
                    INITIAL_WINDOW_SIZE=6291456, MAX_FRAME_SIZE=16384, MAX_HEADER_LIST_SIZE=262144
        - WINDOW_UPDATE: 15663105 (bringing window to 15728640)
        - Pseudo-header order: :method, :authority, :scheme, :path
        """
        config = HTTP2FingerprintConfig()

        # Chrome SETTINGS in exact order
        config.settings = [
            (HTTP2Setting.HEADER_TABLE_SIZE, 65536),
            (HTTP2Setting.ENABLE_PUSH, 0),
            (HTTP2Setting.MAX_CONCURRENT_STREAMS, 1000),
            (HTTP2Setting.INITIAL_WINDOW_SIZE, 6291456),  # 6MB
            (HTTP2Setting.MAX_FRAME_SIZE, 16384),
            (HTTP2Setting.MAX_HEADER_LIST_SIZE, 262144),
            (HTTP2Setting.UNKNOWN_SETTING_8, 1),  # Chrome 130+ uses this
        ]

        # Chrome WINDOW_UPDATE: 15728640 - 65535 = 15663105
        config.window_update_increment = 15663105

        # Chrome pseudo-header order
        config.pseudo_header_order = [":method", ":authority", ":scheme", ":path"]

        # Chrome header order (typical)
        config.header_order = [
            "accept",
            "accept-encoding",
            "accept-language",
            "cache-control",
            "cookie",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "upgrade-insecure-requests",
            "user-agent",
        ]

        config.enable_priority = True
        config.priority_stream_id = 3
        config.priority_weight = 200

        return config

    @staticmethod
    def chrome_android() -> HTTP2FingerprintConfig:
        """Chrome Android - same as desktop."""
        return HTTP2BrowserFingerprints.chrome()

    @staticmethod
    def firefox() -> HTTP2FingerprintConfig:
        """
        Firefox HTTP/2 fingerprint (Firefox 121+).

        Firefox's HTTP/2 fingerprint:
        - SETTINGS: Different values than Chrome
        - Pseudo-header order: :method, :path, :authority, :scheme
        """
        config = HTTP2FingerprintConfig()

        # Firefox SETTINGS in exact order
        config.settings = [
            (HTTP2Setting.HEADER_TABLE_SIZE, 65536),
            (HTTP2Setting.MAX_CONCURRENT_STREAMS, 100),
            (HTTP2Setting.INITIAL_WINDOW_SIZE, 131072),  # 128KB
            (HTTP2Setting.MAX_FRAME_SIZE, 16384),
            (HTTP2Setting.MAX_HEADER_LIST_SIZE, 262144),
        ]

        config.window_update_increment = 12517377  # Firefox value

        # Firefox pseudo-header order (different from Chrome!)
        config.pseudo_header_order = [":method", ":path", ":authority", ":scheme"]

        # Firefox header order
        config.header_order = [
            "accept",
            "accept-encoding",
            "accept-language",
            "cache-control",
            "cookie",
            "te",
            "upgrade-insecure-requests",
            "user-agent",
        ]

        config.enable_priority = True
        config.priority_stream_id = 3
        config.priority_weight = 201

        return config

    @staticmethod
    def safari() -> HTTP2FingerprintConfig:
        """
        Safari HTTP/2 fingerprint (Safari 17+).

        Safari's HTTP/2 fingerprint:
        - SETTINGS: Different order and values
        - Pseudo-header order: :method, :scheme, :path, :authority
        """
        config = HTTP2FingerprintConfig()

        # Safari SETTINGS in exact order (different from Chrome!)
        config.settings = [
            (HTTP2Setting.MAX_CONCURRENT_STREAMS, 100),
            (HTTP2Setting.INITIAL_WINDOW_SIZE, 6291456),
            (HTTP2Setting.MAX_FRAME_SIZE, 16384),
            (HTTP2Setting.MAX_HEADER_LIST_SIZE, 262144),
            (HTTP2Setting.ENABLE_PUSH, 0),
        ]

        config.window_update_increment = 15663105

        # Safari pseudo-header order (unique!)
        config.pseudo_header_order = [":method", ":scheme", ":path", ":authority"]

        # Safari header order
        config.header_order = [
            "accept",
            "accept-encoding",
            "accept-language",
            "cookie",
            "user-agent",
        ]

        config.enable_priority = True
        config.priority_stream_id = 0
        config.priority_weight = 256

        return config

    @staticmethod
    def edge() -> HTTP2FingerprintConfig:
        """Edge - same as Chrome (Chromium-based)."""
        return HTTP2BrowserFingerprints.chrome()

    @staticmethod
    def get_fingerprint(browser_type: str) -> HTTP2FingerprintConfig:
        """Get HTTP/2 fingerprint for browser type."""
        browsers = {
            "chrome": HTTP2BrowserFingerprints.chrome,
            "chrome_desktop": HTTP2BrowserFingerprints.chrome,
            "chrome_android": HTTP2BrowserFingerprints.chrome_android,
            "firefox": HTTP2BrowserFingerprints.firefox,
            "firefox_desktop": HTTP2BrowserFingerprints.firefox,
            "safari": HTTP2BrowserFingerprints.safari,
            "edge": HTTP2BrowserFingerprints.edge,
        }

        getter = browsers.get(browser_type.lower(), HTTP2BrowserFingerprints.chrome)
        return getter()


class HTTP2FrameBuilder:
    """
    Build HTTP/2 frames with proper fingerprinting.

    This class provides low-level HTTP/2 frame construction
    to match browser fingerprints exactly.
    """

    # Frame types
    FRAME_DATA = 0x0
    FRAME_HEADERS = 0x1
    FRAME_PRIORITY = 0x2
    FRAME_RST_STREAM = 0x3
    FRAME_SETTINGS = 0x4
    FRAME_PUSH_PROMISE = 0x5
    FRAME_PING = 0x6
    FRAME_GOAWAY = 0x7
    FRAME_WINDOW_UPDATE = 0x8
    FRAME_CONTINUATION = 0x9

    # Flags
    FLAG_END_STREAM = 0x1
    FLAG_END_HEADERS = 0x4
    FLAG_PADDED = 0x8
    FLAG_PRIORITY = 0x20
    FLAG_ACK = 0x1

    def __init__(self, config: HTTP2FingerprintConfig):
        self.config = config

    def build_client_preface(self) -> bytes:
        """Build HTTP/2 client connection preface."""
        return self.config.client_preface.encode()

    def build_settings_frame(self, ack: bool = False) -> bytes:
        """
        Build SETTINGS frame.

        The SETTINGS frame is critical for HTTP/2 fingerprinting.
        Akamai and Cloudflare analyze the exact values and order.
        """
        if ack:
            # SETTINGS ACK frame (empty payload)
            return self._build_frame_header(0, self.FRAME_SETTINGS, self.FLAG_ACK, 0)

        # Build settings payload
        payload = bytearray()
        for setting_id, setting_value in self.config.settings:
            # Each setting is 6 bytes: 2 bytes ID + 4 bytes value
            payload.extend(self._pack_setting(setting_id, setting_value))

        return self._build_frame_header(
            len(payload),
            self.FRAME_SETTINGS,
            0,  # No flags for initial SETTINGS
            0,  # Stream ID 0 for connection-level
        ) + bytes(payload)

    def build_window_update_frame(self, stream_id: int = 0) -> bytes:
        """
        Build WINDOW_UPDATE frame.

        The WINDOW_UPDATE value is part of HTTP/2 fingerprint.
        Chrome sends 15663105 for stream 0 after SETTINGS.
        """
        # Window increment is 4 bytes
        payload = self.config.window_update_increment.to_bytes(4, 'big')

        return self._build_frame_header(
            4,  # Always 4 bytes
            self.FRAME_WINDOW_UPDATE,
            0,
            stream_id,
        ) + payload

    def build_headers_frame(
        self,
        stream_id: int,
        headers: Dict[str, str],
        end_stream: bool = True,
        end_headers: bool = True,
    ) -> bytes:
        """
        Build HEADERS frame with proper pseudo-header ordering.

        Pseudo-header ordering is critical for HTTP/2 fingerprinting.
        """
        # Build header block with proper ordering
        header_block = self._build_header_block(headers)

        flags = 0
        if end_stream:
            flags |= self.FLAG_END_STREAM
        if end_headers:
            flags |= self.FLAG_END_HEADERS

        return self._build_frame_header(
            len(header_block),
            self.FRAME_HEADERS,
            flags,
            stream_id,
        ) + header_block

    def build_priority_frame(
        self,
        stream_id: int,
        depends_on: int = 0,
        weight: int = 200,
        exclusive: bool = False,
    ) -> bytes:
        """Build PRIORITY frame."""
        # Priority payload: 5 bytes
        # - Exclusive bit + 31-bit stream dependency
        # - 8-bit weight
        dependency = (depends_on & 0x7FFFFFFF)
        if exclusive:
            dependency |= 0x80000000

        payload = dependency.to_bytes(4, 'big') + bytes([weight - 1])

        return self._build_frame_header(
            5,
            self.FRAME_PRIORITY,
            0,
            stream_id,
        ) + payload

    def build_ping_frame(self, data: bytes = b'\x00' * 8, ack: bool = False) -> bytes:
        """Build PING frame."""
        flags = self.FLAG_ACK if ack else 0
        return self._build_frame_header(
            8,
            self.FRAME_PING,
            flags,
            0,
        ) + (data[:8] if len(data) >= 8 else data.ljust(8, b'\x00'))

    def _build_frame_header(
        self,
        length: int,
        frame_type: int,
        flags: int,
        stream_id: int,
    ) -> bytes:
        """
        Build HTTP/2 frame header.

        Frame header format (9 bytes):
        - Length: 24 bits (3 bytes)
        - Type: 8 bits (1 byte)
        - Flags: 8 bits (1 byte)
        - Reserved: 1 bit
        - Stream Identifier: 31 bits (4 bytes)
        """
        header = bytearray()

        # Length (24 bits)
        header.extend(length.to_bytes(3, 'big'))

        # Type (8 bits)
        header.append(frame_type)

        # Flags (8 bits)
        header.append(flags)

        # Stream ID (31 bits, reserved bit is 0)
        header.extend(stream_id.to_bytes(4, 'big'))

        return bytes(header)

    def _pack_setting(self, setting_id: int, setting_value: int) -> bytes:
        """Pack a single setting."""
        return setting_id.to_bytes(2, 'big') + setting_value.to_bytes(4, 'big')

    def _build_header_block(self, headers: Dict[str, str]) -> bytes:
        """
        Build HPACK header block with proper ordering.

        Uses the hpack library for correct HPACK encoding.
        """
        try:
            import hpack
            encoder = hpack.Encoder()
        except ImportError:
            # Fallback to simplified encoding
            return self._build_header_block_simple(headers)

        # Separate pseudo-headers and regular headers
        pseudo_headers = {}
        regular_headers = {}

        for name, value in headers.items():
            if name.startswith(':'):
                pseudo_headers[name] = value
            else:
                regular_headers[name] = value

        # Build ordered header list
        ordered_headers = []

        # Add pseudo-headers in browser-specific order
        for name in self.config.pseudo_header_order:
            if name in pseudo_headers:
                ordered_headers.append((name, pseudo_headers[name]))

        # Add any remaining pseudo-headers not in order list
        for name, value in pseudo_headers.items():
            if name not in self.config.pseudo_header_order:
                ordered_headers.append((name, value))

        # Add regular headers in browser-specific order
        for name in self.config.header_order:
            if name in regular_headers:
                ordered_headers.append((name, regular_headers[name]))

        # Add remaining headers in alphabetical order
        for name in sorted(regular_headers.keys()):
            if name not in self.config.header_order:
                ordered_headers.append((name, regular_headers[name]))

        return encoder.encode(ordered_headers)

    def _build_header_block_simple(self, headers: Dict[str, str]) -> bytes:
        """Simplified HPACK encoding fallback when hpack library is not available."""
        # Separate pseudo-headers and regular headers
        pseudo_headers = {}
        regular_headers = {}

        for name, value in headers.items():
            if name.startswith(':'):
                pseudo_headers[name] = value
            else:
                regular_headers[name] = value

        # Build ordered header list
        ordered_headers = []

        # Add pseudo-headers in browser-specific order
        for name in self.config.pseudo_header_order:
            if name in pseudo_headers:
                ordered_headers.append((name, pseudo_headers[name]))

        # Add any remaining pseudo-headers
        for name, value in pseudo_headers.items():
            if name not in self.config.pseudo_header_order:
                ordered_headers.append((name, value))

        # Add regular headers in browser-specific order
        for name in self.config.header_order:
            if name in regular_headers:
                ordered_headers.append((name, regular_headers[name]))

        # Add remaining headers
        for name in sorted(regular_headers.keys()):
            if name not in self.config.header_order:
                ordered_headers.append((name, regular_headers[name]))

        return self._encode_headers_hpack(ordered_headers)

    def _encode_headers_hpack(self, headers: List[Tuple[str, str]]) -> bytes:
        """
        Encode headers using HPACK (simplified).

        For production, use the hpack library.
        This is a simplified version for fingerprinting purposes.
        """
        # Simplified HPACK encoding
        # For real implementation, use: from hpack import Encoder
        result = bytearray()

        for name, value in headers:
            # Use literal header field without indexing (simpler)
            # 0x00 = literal header field without indexing

            # Name length and name
            name_bytes = name.encode('utf-8')
            result.append(len(name_bytes))
            result.extend(name_bytes)

            # Value length and value
            value_bytes = value.encode('utf-8')
            result.append(len(value_bytes))
            result.extend(value_bytes)

        return bytes(result)


def get_akamai_fingerprint(config: HTTP2FingerprintConfig) -> str:
    """
    Generate Akamai HTTP/2 fingerprint string.

    Format: S[settings]|WU[window_update]|P[priorities]|PS[pseudo_header_order]
    Example Chrome: 1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,a,s,p
    """
    # Settings part
    settings_str = ";".join(f"{k}:{v}" for k, v in config.settings)

    # Window update
    window_str = str(config.window_update_increment)

    # Priority (simplified)
    priority_str = "0" if config.enable_priority else "1"

    # Pseudo-header order (first letter of each)
    pseudo_str = ",".join(h[1][0] for h in config.pseudo_header_order)

    return f"S{settings_str}|WU{window_str}|P{priority_str}|PS{pseudo_str}"


__all__ = [
    "HTTP2FingerprintConfig",
    "HTTP2BrowserFingerprints",
    "HTTP2FrameBuilder",
    "HTTP2Setting",
    "get_akamai_fingerprint",
]
