"""
TLS Session Management - High-level API for TLS fingerprint management.

Provides easy-to-use classes for managing TLS fingerprints across requests.
Each session maintains a consistent fingerprint for its entire lifetime.
"""

import random
import hashlib
import time
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field

from ._tls_fingerprint import (
    TLSFingerprintConfig,
    TLSFingerprintGenerator,
    BrowserFingerprints,
)


@dataclass
class FingerprintInfo:
    """Information about a TLS fingerprint."""
    browser_type: str
    config: TLSFingerprintConfig
    session_id: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "browser_type": self.browser_type,
            "session_id": self.session_id,
            "created_at": self.created_at,
        }


class TLSSession:
    """
    A TLS session with a consistent fingerprint.

    Once created, the session uses the same TLS fingerprint for all requests.
    This is important for maintaining consistency in TLS handshakes.
    """

    def __init__(
        self,
        browser_type: Optional[str] = None,
        config: Optional[TLSFingerprintConfig] = None,
        session_id: Optional[str] = None,
    ):
        """
        Create a new TLS session.

        Args:
            browser_type: Browser type to mimic. Options:
                - "chrome" / "chrome_desktop" (default)
                - "chrome_android"
                - "firefox" / "firefox_desktop"
                - "safari"
                - "edge"
                - "random" - randomly select a browser
            config: Custom TLS configuration (overrides browser_type)
            session_id: Custom session ID (auto-generated if not provided)
        """
        self._browser_type = browser_type or "chrome"
        self._config = config
        self._session_id = session_id or self._generate_session_id()
        self._generator: Optional[TLSFingerprintGenerator] = None
        self._info: Optional[FingerprintInfo] = None

        # Initialize fingerprint
        self._init_fingerprint()

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        data = f"{time.time()}{random.random()}".encode()
        return hashlib.md5(data).hexdigest()[:16]

    def _init_fingerprint(self) -> None:
        """Initialize the TLS fingerprint for this session."""
        if self._config is not None:
            # Use provided config
            config = self._config
            browser_type = "custom"
        else:
            # Get config based on browser type
            browser_type, config = self._get_browser_config(self._browser_type)

        self._config = config
        self._browser_type = browser_type

        # Create generator and set config
        self._generator = TLSFingerprintGenerator()
        self._generator.set_config(config)

        # Create fingerprint info
        self._info = FingerprintInfo(
            browser_type=browser_type,
            config=config,
            session_id=self._session_id,
        )

    def _get_browser_config(self, browser_type: str) -> tuple:
        """Get browser configuration by type."""
        browser_type_lower = browser_type.lower()

        browsers = {
            "chrome": ("chrome", BrowserFingerprints.chrome_desktop()),
            "chrome_desktop": ("chrome", BrowserFingerprints.chrome_desktop()),
            "chrome_android": ("chrome_android", BrowserFingerprints.chrome_android()),
            "firefox": ("firefox", BrowserFingerprints.firefox_desktop()),
            "firefox_desktop": ("firefox", BrowserFingerprints.firefox_desktop()),
            "safari": ("safari", BrowserFingerprints.safari()),
            "edge": ("edge", BrowserFingerprints.edge()),
        }

        if browser_type_lower == "random":
            # Randomly select a browser
            browser_key = random.choice(list(browsers.keys()))
            return browsers[browser_key]

        if browser_type_lower in browsers:
            return browsers[browser_type_lower]

        # Default to Chrome
        return browsers["chrome"]

    @property
    def session_id(self) -> str:
        """Get the session ID."""
        return self._session_id

    @property
    def browser_type(self) -> str:
        """Get the browser type."""
        return self._browser_type

    @property
    def config(self) -> TLSFingerprintConfig:
        """Get the TLS configuration."""
        return self._config

    @property
    def info(self) -> FingerprintInfo:
        """Get fingerprint information."""
        return self._info

    def generate_client_hello(self, host: str) -> bytes:
        """
        Generate ClientHello data for the given host.

        Args:
            host: The target hostname for SNI extension

        Returns:
            Raw ClientHello bytes
        """
        result = self._generator.generate_client_hello(host)
        # Convert list to bytes if needed
        if isinstance(result, list):
            return bytes(result)
        return result

    def get_client_hello_hex(self, host: str) -> str:
        """
        Generate ClientHello as hex string.

        Args:
            host: The target hostname

        Returns:
            Hex-encoded ClientHello string
        """
        data = self.generate_client_hello(host)
        return data.hex()

    def get_ja3_hash(self) -> str:
        """
        Calculate JA3 fingerprint hash for this session.

        Note: This is a simplified JA3 calculation based on the config.
        For accurate JA3, you need the actual ClientHello bytes.

        Returns:
            JA3 hash string (placeholder - needs actual implementation)
        """
        # Build JA3 string components
        version = "771"  # TLS 1.2 = 0x0303 = 771

        # Cipher suites
        ciphers = ",".join(str(c) for c in self._config.cipher_suites)

        # Extensions (simplified - would need actual extension IDs)
        extensions = "0-5-10-11-13-65281"

        # Named groups (elliptic curves)
        curves = ",".join(str(g) for g in self._config.named_groups)

        # Point formats
        point_formats = "0"

        ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
        return hashlib.md5(ja3_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self._session_id,
            "browser_type": self._browser_type,
            "created_at": self._info.created_at if self._info else time.time(),
            "ja3_hash": self.get_ja3_hash(),
        }

    def __repr__(self) -> str:
        return f"TLSSession(session_id={self._session_id}, browser={self._browser_type})"


class TLSClient:
    """
    TLS Client that manages multiple TLS sessions.

    Use this class when you need to make requests with different
    fingerprints or want to maintain separate session pools.
    """

    def __init__(self, default_browser: str = "chrome"):
        """
        Initialize TLS client.

        Args:
            default_browser: Default browser type for new sessions
        """
        self._default_browser = default_browser
        self._sessions: Dict[str, TLSSession] = {}

    def create_session(
        self,
        browser_type: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> TLSSession:
        """
        Create a new TLS session.

        Args:
            browser_type: Browser type (uses default if not specified)
            session_id: Custom session ID

        Returns:
            New TLSSession instance
        """
        browser = browser_type or self._default_browser
        session = TLSSession(browser_type=browser, session_id=session_id)
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[TLSSession]:
        """
        Get an existing session by ID.

        Args:
            session_id: The session ID

        Returns:
            TLSSession or None if not found
        """
        return self._sessions.get(session_id)

    def remove_session(self, session_id: str) -> bool:
        """
        Remove a session.

        Args:
            session_id: The session ID to remove

        Returns:
            True if removed, False if not found
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all sessions.

        Returns:
            List of session info dictionaries
        """
        return [session.to_dict() for session in self._sessions.values()]

    def clear_sessions(self) -> int:
        """
        Clear all sessions.

        Returns:
            Number of sessions cleared
        """
        count = len(self._sessions)
        self._sessions.clear()
        return count

    @property
    def session_count(self) -> int:
        """Get the number of active sessions."""
        return len(self._sessions)

    def __repr__(self) -> str:
        return f"TLSClient(sessions={self.session_count}, default={self._default_browser})"


class TLSFingerprintPool:
    """
    Pre-generated pool of TLS fingerprints.

    Useful for high-performance scenarios where you want to
    quickly get a random fingerprint without creating new sessions.
    """

    def __init__(
        self,
        pool_size: int = 10,
        browser_types: Optional[List[str]] = None,
    ):
        """
        Initialize the fingerprint pool.

        Args:
            pool_size: Number of fingerprints to pre-generate
            browser_types: List of browser types to use (default: all)
        """
        self._pool_size = pool_size
        self._browser_types = browser_types or [
            "chrome", "chrome_android", "firefox", "safari", "edge"
        ]
        self._pool: List[TLSSession] = []
        self._index = 0

        self._generate_pool()

    def _generate_pool(self) -> None:
        """Pre-generate fingerprint pool."""
        self._pool = []
        for i in range(self._pool_size):
            browser = random.choice(self._browser_types)
            session = TLSSession(browser_type=browser)
            self._pool.append(session)

    def get_random(self) -> TLSSession:
        """
        Get a random fingerprint from the pool.

        Returns:
            A TLSSession with pre-generated fingerprint
        """
        return random.choice(self._pool)

    def get_next(self) -> TLSSession:
        """
        Get the next fingerprint in round-robin order.

        Returns:
            A TLSSession with pre-generated fingerprint
        """
        session = self._pool[self._index]
        self._index = (self._index + 1) % len(self._pool)
        return session

    def refresh(self) -> None:
        """Regenerate the fingerprint pool."""
        self._generate_pool()
        self._index = 0

    @property
    def size(self) -> int:
        """Get the pool size."""
        return len(self._pool)

    def __len__(self) -> int:
        return len(self._pool)

    def __repr__(self) -> str:
        return f"TLSFingerprintPool(size={self.size})"


# Convenience functions for quick usage

def create_session(browser_type: str = "chrome") -> TLSSession:
    """
    Quick function to create a TLS session.

    Args:
        browser_type: Browser type to mimic

    Returns:
        TLSSession instance
    """
    return TLSSession(browser_type=browser_type)


def create_random_session() -> TLSSession:
    """
    Create a session with random browser fingerprint.

    Returns:
        TLSSession with random fingerprint
    """
    return TLSSession(browser_type="random")


def generate_client_hello(host: str, browser_type: str = "chrome") -> bytes:
    """
    Quick function to generate ClientHello for a host.

    Args:
        host: Target hostname
        browser_type: Browser type to mimic

    Returns:
        ClientHello bytes
    """
    session = TLSSession(browser_type=browser_type)
    return session.generate_client_hello(host)


__all__ = [
    "TLSSession",
    "TLSClient",
    "TLSFingerprintPool",
    "FingerprintInfo",
    "create_session",
    "create_random_session",
    "generate_client_hello",
]
