# TLS Fingerprint Library for Python

Chromium-based TLS fingerprint library for Python.

## Installation

### From local source (after building)

```bash
cd tls_for_python/python
pip3 install .
```

### Or using pip with path

```bash
pip3 install /path/to/tls_for_python/python
```

## Quick Start

```python
from tls_fingerprint import BrowserFingerprints, TLSFingerprintGenerator

# Get Chrome browser fingerprint
config = BrowserFingerprints.chrome_desktop()

# Create generator
generator = TLSFingerprintGenerator()
generator.set_config(config)

# Generate ClientHello
client_hello = generator.generate_client_hello("example.com")
print(f"ClientHello size: {len(client_hello)} bytes")
```

## Available Browser Fingerprints

- `BrowserFingerprints.chrome_desktop()` - Chrome Desktop
- `BrowserFingerprints.chrome_android()` - Chrome Android
- `BrowserFingerprints.firefox_desktop()` - Firefox Desktop
- `BrowserFingerprints.safari()` - Safari
- `BrowserFingerprints.edge()` - Edge

## License

BSD 3-Clause License
