"""
TLS HTTP Client with proxy support.

Provides an HTTP client that uses custom TLS fingerprints and supports
HTTP/HTTPS/SOCKS5 proxies.

This client uses BoringSSL for TLS connections to achieve browser-like
TLS fingerprints.
"""

import socket
import struct
import random
import time
import sys
from typing import Optional, Dict, Any, Tuple, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Try to import BoringSSL socket from native module
try:
    from . import _tls_fingerprint as _native
    _has_boringssl = True
except ImportError:
    _has_boringssl = False

from .pure_python import (
    TLSFingerprintConfig,
    TLSFingerprintGenerator,
    BrowserFingerprints,
)
from .session import TLSSession
from .http2_fingerprint import (
    HTTP2BrowserFingerprints,
    HTTP2FrameBuilder,
    HTTP2FingerprintConfig,
)


def _log(debug: bool, msg: str, *args):
    """Print debug log message."""
    if debug:
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] [TLS] {msg}", *args, file=sys.stderr)


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    proxy_type: str = "http"  # http, https, socks5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "proxy_type": self.proxy_type,
        }

    @classmethod
    def from_url(cls, url: str) -> "ProxyConfig":
        """
        Create ProxyConfig from URL.

        Examples:
            http://127.0.0.1:8080
            https://user:pass@proxy.example.com:443
            socks5://127.0.0.1:1080
        """
        parsed = urlparse(url)
        proxy_type = parsed.scheme.lower()
        if proxy_type not in ("http", "https", "socks5"):
            proxy_type = "http"

        return cls(
            host=parsed.hostname or "127.0.0.1",
            port=parsed.port or (1080 if proxy_type == "socks5" else 8080),
            username=parsed.username,
            password=parsed.password,
            proxy_type=proxy_type,
        )


@dataclass
class HttpResponse:
    """HTTP response."""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    http_version: str = "HTTP/1.1"

    @property
    def text(self) -> str:
        """Get response body as text."""
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("latin-1")

    def json(self) -> Any:
        """Parse response body as JSON."""
        import json
        return json.loads(self.text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_size": len(self.body),
            "http_version": self.http_version,
        }


class TLSHttpClient:
    """
    HTTP Client with custom TLS fingerprint and proxy support.

    Features:
    - Custom TLS fingerprint (Chrome, Firefox, Safari, etc.)
    - HTTP/HTTPS/SOCKS5 proxy support
    - Uses BoringSSL for browser-like TLS fingerprints
    - Connection pooling via session
    - Automatic header management
    - Debug logging for troubleshooting

    Example:
        # Simple usage
        client = TLSHttpClient(browser_type="chrome")
        response = client.get("https://example.com")

        # With proxy
        client = TLSHttpClient(
            browser_type="random",
            proxy="http://127.0.0.1:8080"
        )
        response = client.get("https://example.com")

        # With debug logging
        client = TLSHttpClient(browser_type="chrome", debug=True)
        response = client.get("https://example.com")

        # With session (consistent fingerprint)
        session = TLSSession(browser_type="chrome")
        client = TLSHttpClient(session=session)
        r1 = client.get("https://api.example.com/user")
        r2 = client.get("https://api.example.com/data")
    """

    def __init__(
        self,
        browser_type: str = "chrome",
        session: Optional[TLSSession] = None,
        proxy: Optional[Union[str, ProxyConfig]] = None,
        timeout: float = 30.0,
        default_headers: Optional[Dict[str, str]] = None,
        debug: bool = False,
    ):
        """
        Initialize HTTP client.

        Args:
            browser_type: Browser fingerprint type (chrome, firefox, safari, edge, random)
            session: TLSSession to use (overrides browser_type)
            proxy: Proxy URL or ProxyConfig (http://, https://, socks5://)
            timeout: Request timeout in seconds
            default_headers: Default headers to send with every request
            debug: Enable debug logging to see request timing details
        """
        self._session = session or TLSSession(browser_type=browser_type)
        self._proxy = self._parse_proxy(proxy) if proxy else None
        self._timeout = timeout
        self._default_headers = default_headers or {}
        self._generator: Optional[TLSFingerprintGenerator] = None
        self._debug = debug

        # Check if BoringSSL is available
        if not _has_boringssl:
            raise ImportError(
                "BoringSSL native extension is required for TLSHttpClient. "
                "Please rebuild the library with BoringSSL support."
            )

    def _log(self, msg: str, *args):
        """Print debug log message."""
        _log(self._debug, msg, *args)

    def _parse_proxy(self, proxy: Union[str, ProxyConfig]) -> ProxyConfig:
        """Parse proxy configuration."""
        if isinstance(proxy, ProxyConfig):
            return proxy
        return ProxyConfig.from_url(proxy)

    @property
    def session(self) -> TLSSession:
        """Get the TLS session."""
        return self._session

    @property
    def proxy(self) -> Optional[ProxyConfig]:
        """Get proxy configuration."""
        return self._proxy

    def set_proxy(self, proxy: Union[str, ProxyConfig]) -> None:
        """Set proxy configuration."""
        self._proxy = self._parse_proxy(proxy)

    def clear_proxy(self) -> None:
        """Clear proxy configuration."""
        self._proxy = None

    def _get_default_headers(self, host: str, is_https: bool) -> Dict[str, str]:
        """Get default HTTP headers for browser."""
        browser = self._session.browser_type

        # User-Agent based on browser (Chrome 131+)
        user_agents = {
            "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "chrome_android": "Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
            "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
            "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        }

        ua = user_agents.get(browser, user_agents["chrome"])

        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Host": host,
        }

        if is_https:
            headers["Upgrade-Insecure-Requests"] = "1"

        # Merge with custom headers
        headers.update(self._default_headers)
        return headers

    def _connect_via_proxy(self, target_host: str, target_port: int) -> socket.socket:
        """Connect to target via proxy."""
        proxy = self._proxy
        if not proxy:
            raise ValueError("No proxy configured")

        self._log(f"Connecting to proxy {proxy.host}:{proxy.port}...")
        start = time.time()

        # Create socket to proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect((proxy.host, proxy.port))
            self._log(f"Connected to proxy in {time.time()-start:.3f}s")
        except socket.error as e:
            sock.close()
            raise ConnectionError(f"Failed to connect to proxy {proxy.host}:{proxy.port}: {e}")

        if proxy.proxy_type in ("http", "https"):
            # HTTP CONNECT tunneling
            return self._http_connect(sock, target_host, target_port)
        elif proxy.proxy_type == "socks5":
            # SOCKS5 handshake
            return self._socks5_connect(sock, target_host, target_port)
        else:
            sock.close()
            raise ValueError(f"Unsupported proxy type: {proxy.proxy_type}")

    def _http_connect(self, sock: socket.socket, host: str, port: int) -> socket.socket:
        """Perform HTTP CONNECT handshake."""
        proxy = self._proxy
        start = time.time()

        self._log(f"Sending HTTP CONNECT to {host}:{port}...")

        # Build CONNECT request
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\n"
        connect_req += f"Host: {host}:{port}\r\n"

        # Add proxy authentication if needed
        if proxy.username and proxy.password:
            import base64
            credentials = base64.b64encode(
                f"{proxy.username}:{proxy.password}".encode()
            ).decode()
            connect_req += f"Proxy-Authorization: Basic {credentials}\r\n"

        connect_req += "\r\n"

        # Send CONNECT request
        sock.sendall(connect_req.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                raise ConnectionError("Proxy connection closed unexpectedly")
            response += chunk

        # Parse response
        header = response.split(b"\r\n\r\n")[0].decode()
        status_line = header.split("\r\n")[0]

        if "200" not in status_line:
            sock.close()
            raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

        self._log(f"HTTP CONNECT completed in {time.time()-start:.3f}s")
        return sock

    def _socks5_connect(self, sock: socket.socket, host: str, port: int) -> socket.socket:
        """Perform SOCKS5 handshake."""
        proxy = self._proxy
        start = time.time()

        self._log(f"Performing SOCKS5 handshake...")

        # Initial greeting
        if proxy.username and proxy.password:
            # With authentication
            sock.sendall(bytes([5, 2, 0, 2]))  # SOCKS5, 2 methods, no auth + user/pass
        else:
            # No authentication
            sock.sendall(bytes([5, 1, 0]))  # SOCKS5, 1 method, no auth

        # Read server response
        response = sock.recv(2)
        if len(response) < 2:
            sock.close()
            raise ConnectionError("Invalid SOCKS5 response")

        if response[0] != 5:
            sock.close()
            raise ConnectionError(f"Not a SOCKS5 proxy: {response}")

        auth_method = response[1]
        if auth_method == 2:
            # Username/password authentication
            if not proxy.username or not proxy.password:
                sock.close()
                raise ConnectionError("SOCKS5 proxy requires authentication")

            auth_data = bytes([1])  # Version
            auth_data += bytes([len(proxy.username)]) + proxy.username.encode()
            auth_data += bytes([len(proxy.password)]) + proxy.password.encode()
            sock.sendall(auth_data)

            auth_resp = sock.recv(2)
            if len(auth_resp) < 2 or auth_resp[1] != 0:
                sock.close()
                raise ConnectionError("SOCKS5 authentication failed")

        elif auth_method != 0:
            sock.close()
            raise ConnectionError(f"SOCKS5 unsupported auth method: {auth_method}")

        # Send CONNECT request
        request = bytes([5, 1, 0])  # SOCKS5, CONNECT, reserved

        # Add target address
        try:
            ip = socket.inet_aton(host)
            request += bytes([1]) + ip  # IPv4
        except socket.error:
            # Domain name
            request += bytes([3]) + bytes([len(host)]) + host.encode()

        request += struct.pack(">H", port)  # Port

        sock.sendall(request)

        # Read response
        response = sock.recv(10)
        if len(response) < 2:
            sock.close()
            raise ConnectionError("Invalid SOCKS5 connect response")

        if response[1] != 0:
            sock.close()
            errors = {
                1: "General failure",
                2: "Connection not allowed",
                3: "Network unreachable",
                4: "Host unreachable",
                5: "Connection refused",
                6: "TTL expired",
                7: "Command not supported",
                8: "Address type not supported",
            }
            raise ConnectionError(f"SOCKS5 connect failed: {errors.get(response[1], response[1])}")

        self._log(f"SOCKS5 handshake completed in {time.time()-start:.3f}s")
        return sock

    def _create_ssl_context(self):
        """Create SSL context with custom settings (DEPRECATED - uses BoringSSL now)."""
        # This method is kept for compatibility but is no longer used
        # BoringSSLSocket handles TLS internally
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _create_boringssl_socket(self):
        """Create a BoringSSL socket with the session's fingerprint config."""
        sock = _native.BoringSSLSocket()
        sock.set_debug(self._debug)

        # The session config is already a native TLSFingerprintConfig
        # Keep the original ALPN (h2, http/1.1) to match real Chrome TLS fingerprint.
        # Even though we speak HTTP/1.1, the ALPN in ClientHello must advertise h2
        # to match the browser fingerprint. The server will negotiate based on ALPN.
        config = self._session.config

        sock.set_config(config)
        return sock

    def _create_connection(self, host: str, port: int):
        """Create a BoringSSL connection to the target."""
        timeout_ms = int(self._timeout * 1000)

        if self._proxy:
            # Use BoringSSL's built-in proxy support
            sock = self._create_boringssl_socket()
            proxy_type = "socks5" if self._proxy.proxy_type in ("socks5", "socks") else "http"

            self._log(f"Connecting via {proxy_type} proxy {self._proxy.host}:{self._proxy.port}...")
            start = time.time()

            result = sock.connect_via_proxy(
                self._proxy.host,
                self._proxy.port,
                host,
                port,
                proxy_type,
                timeout_ms
            )

            if result != 0:
                error = sock.get_last_error()
                sock.close()
                raise ConnectionError(f"Proxy connection failed: {error}")

            self._log(f"Proxy connection established in {time.time()-start:.3f}s")
            return sock
        else:
            # Direct connection
            self._log(f"Connecting directly to {host}:{port}...")
            start = time.time()

            sock = self._create_boringssl_socket()
            result = sock.connect(host, port, timeout_ms)

            if result != 0:
                error = sock.get_last_error()
                sock.close()
                raise ConnectionError(f"Connection failed: {error}")

            self._log(f"Direct connection established in {time.time()-start:.3f}s")
            return sock

    def _get_negotiated_protocol(self, sock) -> str:
        """Get the ALPN negotiated protocol from the connection."""
        try:
            info = sock.get_connection_info()
            proto = info.negotiated_protocol
            if proto:
                self._log(f"Negotiated ALPN protocol: {proto}")
                return proto
        except Exception:
            pass
        return "http/1.1"

    def _send_h2_request(self, sock, method: str, path: str, host: str,
                          headers: Optional[Dict[str, str]] = None,
                          body: Optional[bytes] = None) -> HttpResponse:
        """Send HTTP/2 request with proper fingerprinting frames."""
        try:
            import hpack
            encoder = hpack.Encoder()
            use_hpack = True
        except ImportError:
            use_hpack = False

        browser_type = self._session.browser_type
        h2_config = HTTP2BrowserFingerprints.get_fingerprint(browser_type)
        frame_builder = HTTP2FrameBuilder(h2_config)

        # 1. Send HTTP/2 connection preface + SETTINGS + WINDOW_UPDATE together
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings_frame = frame_builder.build_settings_frame()
        window_update = frame_builder.build_window_update_frame(stream_id=0)
        sock.send(preface + settings_frame + window_update)
        self._log("Sent HTTP/2 connection preface + SETTINGS + WINDOW_UPDATE")

        # 2. Read server's initial frames, process SETTINGS and keep leftover
        leftover = b""
        import time as _time
        _time.sleep(0.05)
        try:
            server_data = sock.recv(16384)
            if server_data:
                self._log(f"Received server initial data ({len(server_data)} bytes)")
                # Parse frames: ACK any SETTINGS, keep unprocessed data
                pos = 0
                while pos + 9 <= len(server_data):
                    frame_len = int.from_bytes(server_data[pos:pos+3], 'big')
                    frame_type = server_data[pos+3]
                    frame_flags = server_data[pos+4]
                    total = 9 + frame_len
                    if pos + total > len(server_data):
                        # Incomplete frame - keep from here
                        break
                    if frame_type == 0x04 and not (frame_flags & 0x01):
                        # SETTINGS (not ACK) - send ACK
                        sock.send(b'\x00\x00\x00\x04\x01\x00\x00\x00\x00')
                        self._log("Sent SETTINGS ACK")
                    elif frame_type == 0x04 and (frame_flags & 0x01):
                        # SETTINGS ACK from server - skip
                        pass
                    elif frame_type == 0x08:
                        # WINDOW_UPDATE - skip
                        pass
                    else:
                        # Any other frame (HEADERS, DATA, GOAWAY, etc.) - keep for response reader
                        leftover += server_data[pos:pos+total]
                    pos += total
                # Keep any trailing incomplete data
                if pos < len(server_data):
                    leftover += server_data[pos:]
        except Exception:
            pass

        # 3. Build headers for the request
        req_headers = self._get_default_headers(host, True)
        if headers:
            req_headers.update(headers)

        # Build pseudo-headers + regular headers
        if use_hpack:
            headers_list = [
                (':method', method),
                (':authority', host),
                (':scheme', 'https'),
                (':path', path),
            ]
            for k, v in req_headers.items():
                if k.lower() in ("host", "connection", "transfer-encoding"):
                    continue
                headers_list.append((k.lower(), v))

            encoded = encoder.encode(headers_list)
        else:
            all_headers = {
                ':method': method,
                ':authority': host,
                ':scheme': 'https',
                ':path': path,
            }
            for k, v in req_headers.items():
                if k.lower() in ("host", "connection", "transfer-encoding"):
                    continue
                all_headers[k.lower()] = v
            encoded = frame_builder._build_header_block(all_headers)

        # 4. Send HEADERS frame on stream 1
        end_stream = body is None
        flags = 0x04  # END_HEADERS
        if end_stream:
            flags |= 0x01  # END_STREAM
        hdr_frame = len(encoded).to_bytes(3, 'big') + bytes([0x01, flags]) + (1).to_bytes(4, 'big') + encoded
        sock.send(hdr_frame)
        self._log("Sent HTTP/2 HEADERS frame")

        # 5. Send DATA frame if body exists
        if body:
            data_frame = self._build_h2_data_frame(body, stream_id=1, end_stream=True)
            sock.send(data_frame)

        # 6. Read response frames (pass leftover as pre-read data)
        return self._read_h2_response(sock, initial_buf=leftover)

    def _build_h2_data_frame(self, data: bytes, stream_id: int, end_stream: bool) -> bytes:
        """Build HTTP/2 DATA frame."""
        flags = 0x01 if end_stream else 0x00  # END_STREAM
        header = len(data).to_bytes(3, 'big')  # length
        header += b'\x00'  # type = DATA
        header += bytes([flags])
        header += stream_id.to_bytes(4, 'big')
        return header + data

    def _read_h2_response(self, sock, initial_buf: bytes = b"") -> HttpResponse:
        """Read and parse HTTP/2 response frames."""
        try:
            import hpack
            decoder = hpack.Decoder()
        except ImportError:
            decoder = None

        response_headers = {}
        response_body = b""
        status_code = 200
        stream_ended = False
        goaway_received = False

        buf = initial_buf
        max_reads = 200
        import time as _time

        for _ in range(max_reads):
            if stream_ended:
                break

            # Only read from socket if buffer doesn't have a complete frame
            if len(buf) < 9 or len(buf) < 9 + int.from_bytes(buf[0:3], 'big'):
                try:
                    chunk = sock.recv(16384)
                except Exception:
                    if buf:
                        # Process remaining buffer before breaking
                        pass
                    else:
                        break
                else:
                    if not chunk:
                        break
                    buf += chunk

            # Parse frames from buffer
            while len(buf) >= 9:
                frame_len = int.from_bytes(buf[0:3], 'big')
                frame_type = buf[3]
                frame_flags = buf[4]
                frame_stream_id = int.from_bytes(buf[5:9], 'big') & 0x7FFFFFFF

                total_frame_len = 9 + frame_len
                if len(buf) < total_frame_len:
                    break  # Need more data

                frame_payload = buf[9:total_frame_len]
                buf = buf[total_frame_len:]

                if frame_type == 0x04:  # SETTINGS
                    if not (frame_flags & 0x01):  # Not ACK
                        ack = b'\x00\x00\x00\x04\x01\x00\x00\x00\x00'
                        sock.send(ack)
                        self._log("Sent SETTINGS ACK")

                elif frame_type == 0x01 and frame_stream_id == 1:  # HEADERS on our stream
                    if decoder:
                        try:
                            decoded = decoder.decode(frame_payload)
                            for name, value in decoded:
                                response_headers[name] = value
                        except Exception as e:
                            self._log(f"HPACK decode error: {e}")
                    else:
                        self._parse_h2_headers(frame_payload, response_headers)

                    if ":status" in response_headers:
                        status_code = int(response_headers[":status"])
                        del response_headers[":status"]

                    if frame_flags & 0x01:  # END_STREAM
                        stream_ended = True

                elif frame_type == 0x00 and frame_stream_id == 1:  # DATA on our stream
                    response_body += frame_payload
                    if frame_flags & 0x01:  # END_STREAM
                        stream_ended = True

                    # Send WINDOW_UPDATE for received data
                    if frame_len > 0:
                        wu_payload = frame_len.to_bytes(4, 'big')
                        wu_frame = (4).to_bytes(3, 'big') + b'\x08\x00' + (0).to_bytes(4, 'big') + wu_payload
                        sock.send(wu_frame)

                elif frame_type == 0x07:  # GOAWAY
                    goaway_received = True
                    # Don't stop immediately - we may still receive data for stream 1
                    self._log("Received GOAWAY, continuing to read stream 1")

                elif frame_type == 0x06:  # PING
                    if not (frame_flags & 0x01):
                        ping_ack = (8).to_bytes(3, 'big') + b'\x06\x01' + (0).to_bytes(4, 'big') + frame_payload
                        sock.send(ping_ack)

                elif frame_type == 0x08:  # WINDOW_UPDATE
                    pass

        # Handle decompression
        content_encoding = response_headers.get("content-encoding", "").lower()
        if content_encoding == "gzip":
            response_body = self._decompress_gzip(response_body)
        elif content_encoding == "br":
            try:
                import brotli
                response_body = brotli.decompress(response_body)
            except ImportError:
                self._log("Warning: brotli not installed, cannot decompress br content")
            except Exception as e:
                self._log(f"Warning: brotli decompress failed: {e}")

        return HttpResponse(
            status_code=status_code,
            headers=response_headers,
            body=response_body,
            http_version="HTTP/2",
        )

    def _parse_h2_headers(self, data: bytes, headers: Dict[str, str]) -> None:
        """Parse simplified HPACK encoded headers from HTTP/2 HEADERS frame."""
        pos = 0
        while pos < len(data):
            byte = data[pos]

            if byte & 0x80:  # Indexed Header Field
                # Static table lookup (simplified)
                index = byte & 0x7F
                if index == 0:
                    break
                # Common static table entries
                static_headers = {
                    2: (":method", "GET"),
                    3: (":method", "POST"),
                    4: (":path", "/"),
                    5: (":path", "/index.html"),
                    6: (":scheme", "http"),
                    7: (":scheme", "https"),
                    8: (":status", "200"),
                    9: (":status", "204"),
                    10: (":status", "206"),
                    11: (":status", "304"),
                    12: (":status", "400"),
                    13: (":status", "404"),
                    14: (":status", "500"),
                }
                if index in static_headers:
                    name, value = static_headers[index]
                    headers[name] = value
                pos += 1

            elif byte & 0x40:  # Literal Header Field with Incremental Indexing
                name_index = byte & 0x3F
                pos += 1
                if name_index > 0:
                    # Name from static table
                    static_names = {
                        1: ":authority", 8: ":status", 15: "accept-charset",
                        16: "accept-encoding", 17: "accept-language", 19: "accept-ranges",
                        22: "allow", 23: "authorization", 24: "cache-control",
                        25: "content-disposition", 26: "content-encoding",
                        28: "content-length", 29: "content-location",
                        31: "content-type", 32: "cookie", 33: "date",
                        35: "expires", 37: "host", 40: "last-modified",
                        44: "location", 46: "proxy-authenticate",
                        50: "retry-after", 51: "server", 54: "set-cookie",
                        55: "strict-transport-security", 57: "transfer-encoding",
                        58: "user-agent", 60: "via", 61: "www-authenticate",
                    }
                    name = static_names.get(name_index, f"header-{name_index}")
                    # Read value
                    if pos < len(data):
                        value_len = data[pos] & 0x7F
                        huffman = bool(data[pos] & 0x80)
                        pos += 1
                        if pos + value_len <= len(data):
                            value = data[pos:pos+value_len].decode('utf-8', errors='replace')
                            headers[name] = value
                            pos += value_len
                        else:
                            break
                    else:
                        break
                else:
                    # Literal name
                    if pos >= len(data):
                        break
                    name_len = data[pos] & 0x7F
                    pos += 1
                    if pos + name_len > len(data):
                        break
                    name = data[pos:pos+name_len].decode('utf-8', errors='replace')
                    pos += name_len
                    if pos >= len(data):
                        break
                    value_len = data[pos] & 0x7F
                    pos += 1
                    if pos + value_len > len(data):
                        break
                    value = data[pos:pos+value_len].decode('utf-8', errors='replace')
                    headers[name] = value
                    pos += value_len

            elif byte & 0x20:  # Dynamic Table Size Update
                pos += 1  # Skip

            else:  # Literal Header Field without Indexing / Never Indexed
                name_index = byte & 0x0F
                pos += 1
                if name_index > 0:
                    static_names = {
                        1: ":authority", 8: ":status",
                        26: "content-encoding", 28: "content-length",
                        31: "content-type",
                    }
                    name = static_names.get(name_index, f"header-{name_index}")
                    if pos >= len(data):
                        break
                    value_len = data[pos] & 0x7F
                    pos += 1
                    if pos + value_len > len(data):
                        break
                    value = data[pos:pos+value_len].decode('utf-8', errors='replace')
                    headers[name] = value
                    pos += value_len
                else:
                    if pos >= len(data):
                        break
                    name_len = data[pos] & 0x7F
                    pos += 1
                    if pos + name_len > len(data):
                        break
                    name = data[pos:pos+name_len].decode('utf-8', errors='replace')
                    pos += name_len
                    if pos >= len(data):
                        break
                    value_len = data[pos] & 0x7F
                    pos += 1
                    if pos + value_len > len(data):
                        break
                    value = data[pos:pos+value_len].decode('utf-8', errors='replace')
                    headers[name] = value
                    pos += value_len

    def _wrap_ssl(self, sock, host: str):
        """Wrap socket with SSL (DEPRECATED - BoringSSLSocket handles this internally)."""
        # BoringSSLSocket already has SSL/TLS handled
        return sock

    def _parse_response(self, data: bytes) -> HttpResponse:
        """Parse HTTP response."""
        # Split headers and body
        if b"\r\n\r\n" in data:
            header_data, body = data.split(b"\r\n\r\n", 1)
        else:
            header_data = data
            body = b""

        # Parse status line
        header_lines = header_data.decode("latin-1").split("\r\n")
        status_line = header_lines[0]
        parts = status_line.split(" ", 2)

        http_version = parts[0] if len(parts) > 0 else "HTTP/1.1"
        status_code = int(parts[1]) if len(parts) > 1 else 0

        # Parse headers
        headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        # Handle chunked transfer encoding
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._decode_chunked(body)

        # Handle content-length
        elif "content-length" in headers:
            content_length = int(headers["content-length"])
            # Body might be incomplete, but we return what we have

        # Handle gzip encoding
        if headers.get("content-encoding", "").lower() == "gzip":
            body = self._decompress_gzip(body)

        return HttpResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            http_version=http_version,
        )

    def _decode_chunked(self, data: bytes) -> bytes:
        """Decode chunked transfer encoding."""
        result = b""
        pos = 0

        while pos < len(data):
            # Find chunk size
            end = data.find(b"\r\n", pos)
            if end == -1:
                break

            size_hex = data[pos:end].decode("ascii").strip()
            try:
                chunk_size = int(size_hex, 16)
            except ValueError:
                break

            if chunk_size == 0:
                break

            # Read chunk data
            start = end + 2
            result += data[start:start + chunk_size]
            pos = start + chunk_size + 2  # Skip chunk data and trailing \r\n

        return result

    def _decompress_gzip(self, data: bytes) -> bytes:
        """Decompress gzip data."""
        import gzip
        import io
        try:
            return gzip.decompress(data)
        except Exception:
            return data

    def _build_request(
        self,
        method: str,
        path: str,
        host: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> bytes:
        """Build HTTP request."""
        # Get default headers
        req_headers = self._get_default_headers(host, True)

        # Merge with custom headers
        if headers:
            req_headers.update(headers)

        # Build request line
        request = f"{method} {path} HTTP/1.1\r\n"

        # Add headers
        for key, value in req_headers.items():
            request += f"{key}: {value}\r\n"

        # Add body length if needed
        if body:
            request += f"Content-Length: {len(body)}\r\n"

        request += "\r\n"

        result = request.encode()
        if body:
            result += body

        return result

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        """
        Send HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Additional headers
            body: Request body (bytes, string, or dict for form data)
            timeout: Request timeout (overrides default)

        Returns:
            HttpResponse object
        """
        total_start = time.time()
        self._log(f"=== Starting {method} request to {url} ===")

        # Parse URL
        self._log("Parsing URL...")
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        is_https = parsed.scheme == "https"
        self._log(f"Target: {host}:{port}, path={path}, https={is_https}")

        # Prepare body
        req_body = None
        if body is not None:
            if isinstance(body, dict):
                import urllib.parse
                req_body = urllib.parse.urlencode(body).encode()
                if headers is None:
                    headers = {}
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(body, str):
                req_body = body.encode()
            else:
                req_body = body

        # DNS resolution (prefer IPv4 to avoid IPv6 timeout delays)
        dns_start = time.time()
        self._log(f"Resolving DNS for {host}...")
        try:
            # Use getaddrinfo with IPv4 only to avoid 30s IPv6 timeout
            addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            if addr_info:
                ip = addr_info[0][4][0]
            else:
                ip = socket.gethostbyname(host)
            self._log(f"DNS resolved: {host} -> {ip} ({time.time()-dns_start:.3f}s)")
        except socket.gaierror as e:
            self._log(f"DNS resolution failed: {e}")
            raise

        # Create connection
        conn_start = time.time()
        sock = self._create_connection(host, port)
        self._log(f"Connection phase took {time.time()-conn_start:.3f}s")

        try:
            # Check negotiated ALPN protocol
            negotiated = self._get_negotiated_protocol(sock)

            if negotiated == "h2":
                # HTTP/2 path with proper fingerprinting
                self._log("Using HTTP/2 protocol")
                response = self._send_h2_request(sock, method, path, host, headers, req_body)
                self._log(f"=== Request completed in {time.time()-total_start:.3f}s (status: {response.status_code}) ===")
                return response

            # HTTP/1.1 path (fallback)
            self._log("Using HTTP/1.1 protocol")

            # Build and send request
            send_start = time.time()
            request_data = self._build_request(method, path, host, headers, req_body)
            self._log(f"Sending request ({len(request_data)} bytes)...")
            sock.send(request_data)
            self._log(f"Request sent in {time.time()-send_start:.3f}s")

            # Read response
            recv_start = time.time()
            self._log("Waiting for response...")
            response_data = b""
            # Note: timeout is handled at connect time for BoringSSLSocket
            response_complete = False

            while not response_complete:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        self._log("Connection closed by server")
                        break
                    response_data += chunk
                    self._log(f"Received {len(chunk)} bytes (total: {len(response_data)})")

                    # Check if we have complete headers
                    if b"\r\n\r\n" in response_data:
                        # For simple responses without body or with content-length
                        # we can stop here
                        header_part = response_data.split(b"\r\n\r\n")[0]
                        if b"Content-Length:" in header_part:
                            # Parse content length
                            for line in header_part.decode().split("\r\n"):
                                if line.lower().startswith("content-length:"):
                                    content_length = int(line.split(":")[1].strip())
                                    body_start = response_data.find(b"\r\n\r\n") + 4
                                    if len(response_data) >= body_start + content_length:
                                        self._log("Response complete (Content-Length satisfied)")
                                        response_complete = True
                                    break  # Break out of for loop
                        elif b"Transfer-Encoding: chunked" in header_part:
                            # Chunked encoding - read until 0\r\n\r\n
                            if b"\r\n0\r\n\r\n" in response_data:
                                self._log("Response complete (chunked encoding done)")
                                response_complete = True
                        else:
                            # No content-length, read until connection closes
                            pass
                except socket.timeout:
                    self._log("Socket timeout while reading response")
                    break

            self._log(f"Response received in {time.time()-recv_start:.3f}s (total: {len(response_data)} bytes)")

            response = self._parse_response(response_data)
            self._log(f"=== Request completed in {time.time()-total_start:.3f}s (status: {response.status_code}) ===")
            return response

        finally:
            sock.close()

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        """Send GET request."""
        return self.request("GET", url, headers=headers, **kwargs)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        **kwargs
    ) -> HttpResponse:
        """Send POST request."""
        return self.request("POST", url, headers=headers, body=body, **kwargs)

    def put(self, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[Union[bytes, str, Dict[str, Any]]] = None, **kwargs) -> HttpResponse:
        """Send PUT request."""
        return self.request("PUT", url, headers=headers, body=body, **kwargs)

    def delete(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        """Send DELETE request."""
        return self.request("DELETE", url, headers=headers, **kwargs)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        """Send HEAD request."""
        return self.request("HEAD", url, headers=headers, **kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Get client info as dictionary."""
        return {
            "browser_type": self._session.browser_type,
            "session_id": self._session.session_id,
            "proxy": self._proxy.to_dict() if self._proxy else None,
            "timeout": self._timeout,
        }


# Convenience functions

def get(
    url: str,
    browser_type: str = "chrome",
    proxy: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    debug: bool = False,
    **kwargs
) -> HttpResponse:
    """
    Quick GET request with custom TLS fingerprint.

    Args:
        url: Target URL
        browser_type: Browser fingerprint type
        proxy: Proxy URL (http://, https://, socks5://)
        headers: Additional headers
        debug: Enable debug logging

    Returns:
        HttpResponse object
    """
    client = TLSHttpClient(browser_type=browser_type, proxy=proxy, debug=debug)
    return client.get(url, headers=headers, **kwargs)


def post(
    url: str,
    browser_type: str = "chrome",
    proxy: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    debug: bool = False,
    **kwargs
) -> HttpResponse:
    """
    Quick POST request with custom TLS fingerprint.

    Args:
        url: Target URL
        browser_type: Browser fingerprint type
        proxy: Proxy URL
        headers: Additional headers
        body: Request body
        debug: Enable debug logging

    Returns:
        HttpResponse object
    """
    client = TLSHttpClient(browser_type=browser_type, proxy=proxy, debug=debug)
    return client.post(url, headers=headers, body=body, **kwargs)


__all__ = [
    "TLSHttpClient",
    "ProxyConfig",
    "HttpResponse",
    "get",
    "post",
]
