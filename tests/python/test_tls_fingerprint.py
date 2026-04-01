"""
TLS Fingerprint Library - Python Tests
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class TestTLSFingerprintConfig(unittest.TestCase):
    """Test TLSFingerprintConfig class."""

    def test_default_config(self):
        """Test default configuration values."""
        try:
            from tls_fingerprint import TLSFingerprintConfig
            config = TLSFingerprintConfig()

            # Check default TLS versions
            self.assertEqual(config.version_min, 0x0303)  # TLS 1.2
            self.assertEqual(config.version_max, 0x0304)  # TLS 1.3

            # Check default extension settings
            self.assertTrue(config.permute_extensions)
            self.assertTrue(config.enable_grease)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")


class TestBrowserFingerprints(unittest.TestCase):
    """Test BrowserFingerprints class."""

    def test_chrome_desktop(self):
        """Test Chrome desktop fingerprint."""
        try:
            from tls_fingerprint import BrowserFingerprints

            config = BrowserFingerprints.chrome_desktop()

            # Verify basic properties
            self.assertIsNotNone(config)
            self.assertGreater(len(config.cipher_suites), 0)
            self.assertGreater(len(config.signature_algorithms), 0)
            self.assertGreater(len(config.named_groups), 0)

            # Verify first cipher suite is TLS 1.3
            self.assertEqual(config.cipher_suites[0], 0x1301)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")

    def test_firefox_desktop(self):
        """Test Firefox desktop fingerprint."""
        try:
            from tls_fingerprint import BrowserFingerprints

            config = BrowserFingerprints.firefox_desktop()

            self.assertIsNotNone(config)
            self.assertGreater(len(config.cipher_suites), 0)

            # Firefox doesn't permute extensions
            self.assertFalse(config.permute_extensions)
            self.assertFalse(config.enable_grease)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")

    def test_safari(self):
        """Test Safari fingerprint."""
        try:
            from tls_fingerprint import BrowserFingerprints

            config = BrowserFingerprints.safari()

            self.assertIsNotNone(config)
            self.assertGreater(len(config.cipher_suites), 0)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")


class TestTLSFingerprintGenerator(unittest.TestCase):
    """Test TLSFingerprintGenerator class."""

    def test_generator_creation(self):
        """Test generator creation."""
        try:
            from tls_fingerprint import TLSFingerprintGenerator, BrowserFingerprints

            config = BrowserFingerprints.chrome_desktop()
            generator = TLSFingerprintGenerator()
            generator.set_config(config)

            self.assertIsNotNone(generator)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")

    def test_generate_client_hello(self):
        """Test ClientHello generation."""
        try:
            from tls_fingerprint import TLSFingerprintGenerator, BrowserFingerprints

            config = BrowserFingerprints.chrome_desktop()
            generator = TLSFingerprintGenerator()
            generator.set_config(config)

            client_hello = generator.generate_client_hello("example.com")

            self.assertIsNotNone(client_hello)
            self.assertGreater(len(client_hello), 0)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")


class TestConfigLoader(unittest.TestCase):
    """Test ConfigLoader class."""

    def test_load_from_json_string(self):
        """Test loading configuration from JSON string."""
        try:
            from tls_fingerprint import ConfigLoader

            json_content = '''
            {
                "version_min": "TLS1.2",
                "version_max": "TLS1.3",
                "cipher_suites": [
                    {"id": "0x1301", "name": "TLS_AES_128_GCM_SHA256"}
                ]
            }
            '''

            config = ConfigLoader.from_json(json_content)
            self.assertIsNotNone(config)

        except ImportError:
            self.skipTest("tls_fingerprint module not built")

    def test_load_from_file(self):
        """Test loading configuration from file."""
        try:
            from tls_fingerprint import ConfigLoader

            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "configs", "chrome_120_desktop.json"
            )

            if os.path.exists(config_path):
                config = ConfigLoader.from_file(config_path)
                self.assertIsNotNone(config)
            else:
                self.skipTest("Config file not found")

        except ImportError:
            self.skipTest("tls_fingerprint module not built")


if __name__ == "__main__":
    unittest.main()
