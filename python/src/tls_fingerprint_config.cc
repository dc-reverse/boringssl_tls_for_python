// TLS Fingerprint Library - Standalone Configuration Implementation
// Extracted and simplified from Chromium source code

#include "tls_fingerprint/tls_fingerprint_config.h"
#include <unordered_map>

namespace tls_fingerprint {

namespace {

// Cipher suite name mapping
const std::unordered_map<uint16_t, const char*> kCipherSuiteNames = {
    // TLS 1.3
    {0x1301, "TLS_AES_128_GCM_SHA256"},
    {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},

    // TLS 1.2
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},

    // TLS 1.2 (legacy)
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
};

// Signature algorithm name mapping
const std::unordered_map<uint16_t, const char*> kSignatureAlgorithmNames = {
    {0x0201, "RSA_PKCS1_SHA1"},
    {0x0301, "ECDSA_SHA1"},
    {0x0401, "RSA_PKCS1_SHA256"},
    {0x0501, "RSA_PKCS1_SHA384"},
    {0x0601, "RSA_PKCS1_SHA512"},
    {0x0403, "ECDSA_SECP256R1_SHA256"},
    {0x0503, "ECDSA_SECP384R1_SHA384"},
    {0x0603, "ECDSA_SECP521R1_SHA512"},
    {0x0804, "RSA_PSS_RSAE_SHA256"},
    {0x0805, "RSA_PSS_RSAE_SHA384"},
    {0x0806, "RSA_PSS_RSAE_SHA512"},
    {0x0807, "ED25519"},
    {0x0808, "ED448"},
    {0x0809, "RSA_PSS_PSS_SHA256"},
    {0x080A, "RSA_PSS_PSS_SHA384"},
    {0x080B, "RSA_PSS_PSS_SHA512"},
};

// Named group name mapping
const std::unordered_map<uint16_t, const char*> kNamedGroupNames = {
    {0x0017, "secp256r1"},
    {0x0018, "secp384r1"},
    {0x0019, "secp521r1"},
    {0x001D, "x25519"},
    {0x001E, "x448"},
    {0x0100, "ffdhe2048"},
    {0x0101, "ffdhe3072"},
    {0x0102, "ffdhe4096"},
    {0x0103, "ffdhe6144"},
    {0x0104, "ffdhe8192"},
    {0x11EC, "x25519_mlkem768"},
};

}  // namespace

// Browser fingerprint implementations
// Based on real browser TLS fingerprints (Chrome 120+, Firefox 121+, Safari 17+)

TLSFingerprintConfig BrowserFingerprints::ChromeDesktop() {
    TLSFingerprintConfig config;

    config.version_min = SSL_PROTOCOL_VERSION_TLS1_2;
    config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;

    // Chrome 131 cipher suites (15 suites, matching real browser)
    config.cipher_suites = {
        0x1301,  // TLS_AES_128_GCM_SHA256
        0x1302,  // TLS_AES_256_GCM_SHA384
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256
        0xC02B,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02C,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCA9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        // Legacy cipher suites (required for real Chrome fingerprint)
        0xC013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009C,  // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D,  // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002F,  // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
    };

    // Chrome 131+ signature algorithms (exact match, 13 algorithms)
    // Only algorithms actually supported by BoringSSL/Chrome
    config.signature_algorithms = {
        0x0403,  // ecdsa_secp256r1_sha256
        0x0503,  // ecdsa_secp384r1_sha384
        0x0603,  // ecdsa_secp521r1_sha512
        0x0804,  // rsa_pss_rsae_sha256
        0x0805,  // rsa_pss_rsae_sha384
        0x0806,  // rsa_pss_rsae_sha512
        0x0401,  // rsa_pkcs1_sha256
        0x0501,  // rsa_pkcs1_sha384
        0x0601,  // rsa_pkcs1_sha512
        0x0201,  // rsa_pkcs1_sha1 (legacy)
        0x0203,  // ecdsa_sha1 (legacy)
        0x0807,  // ed25519
        0x0420,  // rsa_pkcs1_sha256_legacy
    };

    // Chrome 131+ named groups (includes post-quantum hybrid)
    config.named_groups = {
        0x11EC,  // x25519_mlkem768 (4588) - post-quantum hybrid
        0x001D,  // x25519 (29)
        0x0017,  // secp256r1 (23)
        0x0018,  // secp384r1 (24)
        0x0019,  // secp521r1 (25)
    };

    // ALPN protocols
    config.alpn_protocols = {"h2", "http/1.1"};

    // Extension settings
    config.permute_extensions = true;
    config.enable_grease = true;
    config.enable_ech = false;

    return config;
}

TLSFingerprintConfig BrowserFingerprints::ChromeAndroid() {
    // Android Chrome uses same fingerprint as desktop in recent versions
    return ChromeDesktop();
}

TLSFingerprintConfig BrowserFingerprints::FirefoxDesktop() {
    TLSFingerprintConfig config;

    config.version_min = SSL_PROTOCOL_VERSION_TLS1_2;
    config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;

    // Firefox cipher suites (15 suites, Firefox order: CHACHA20 between GCM-128 and GCM-256)
    config.cipher_suites = {
        0x1301,  // TLS_AES_128_GCM_SHA256
        0x1302,  // TLS_AES_256_GCM_SHA384
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256
        0xC02B,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02F,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xCCA9,  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xCCA8,  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xC02C,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        // Legacy cipher suites
        0xC013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014,  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009C,  // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D,  // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002F,  // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
    };

    // Firefox signature algorithms (BoringSSL-supported only, 11 algorithms)
    config.signature_algorithms = {
        0x0403,  // ecdsa_secp256r1_sha256
        0x0503,  // ecdsa_secp384r1_sha384
        0x0603,  // ecdsa_secp521r1_sha512
        0x0804,  // rsa_pss_rsae_sha256
        0x0805,  // rsa_pss_rsae_sha384
        0x0806,  // rsa_pss_rsae_sha512
        0x0401,  // rsa_pkcs1_sha256
        0x0501,  // rsa_pkcs1_sha384
        0x0601,  // rsa_pkcs1_sha512
        0x0807,  // ed25519
        0x0201,  // rsa_pkcs1_sha1
    };

    // Firefox named groups (BoringSSL-supported only, no ffdhe)
    config.named_groups = {
        0x001D,  // x25519
        0x0017,  // secp256r1
        0x0018,  // secp384r1
    };

    config.alpn_protocols = {"h2", "http/1.1"};

    // Firefox doesn't permute extensions or use GREASE
    config.permute_extensions = false;
    config.enable_grease = false;

    return config;
}

TLSFingerprintConfig BrowserFingerprints::Safari() {
    TLSFingerprintConfig config;

    config.version_min = SSL_PROTOCOL_VERSION_TLS1_2;
    config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;

    // Safari cipher suites - Real Safari: 4866-4867-4865-49195-49199-49196-49200
    // Has TLS 1.3 CHACHA20 (0x1303=4867), but NO TLS 1.2 CHACHA20 (0xCCA9/0xCCA8)
    config.cipher_suites = {
        0x1302,  // TLS_AES_256_GCM_SHA384 (4866) - Safari puts AES256 first
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256 (4867) - TLS 1.3 CHACHA20 is OK
        0x1301,  // TLS_AES_128_GCM_SHA256 (4865)
        0xC02B,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (49195)
        0xC02F,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (49199)
        0xC02C,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (49196)
        0xC030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (49200)
        // NO 0xCCA9/0xCCA8 - Safari doesn't support TLS 1.2 CHACHA20
    };

    // Safari signature algorithms (BoringSSL-supported only, 11 algorithms)
    config.signature_algorithms = {
        0x0403,  // ecdsa_secp256r1_sha256
        0x0503,  // ecdsa_secp384r1_sha384
        0x0603,  // ecdsa_secp521r1_sha512
        0x0804,  // rsa_pss_rsae_sha256
        0x0805,  // rsa_pss_rsae_sha384
        0x0806,  // rsa_pss_rsae_sha512
        0x0401,  // rsa_pkcs1_sha256
        0x0501,  // rsa_pkcs1_sha384
        0x0601,  // rsa_pkcs1_sha512
        0x0807,  // ed25519
        0x0201,  // rsa_pkcs1_sha1
    };

    // Real Safari named groups (BoringSSL-supported only, no ffdhe)
    config.named_groups = {
        0x001D,  // x25519
        0x0017,  // secp256r1
        0x0018,  // secp384r1
        0x0019,  // secp521r1
    };

    config.alpn_protocols = {"h2", "http/1.1"};

    // Safari uses GREASE (RFC 8701)
    config.permute_extensions = false;
    config.enable_grease = true;

    return config;
}

TLSFingerprintConfig BrowserFingerprints::Edge() {
    // Edge uses the same fingerprint as Chrome (both Chromium-based)
    return ChromeDesktop();
}

// Name lookup functions

const char* GetCipherSuiteName(uint16_t cipher_suite) {
    auto it = kCipherSuiteNames.find(cipher_suite);
    if (it != kCipherSuiteNames.end()) {
        return it->second;
    }
    return "UNKNOWN";
}

const char* GetCipherSuiteVersion(uint16_t cipher_suite) {
    // TLS 1.3 cipher suites
    if (cipher_suite >= 0x1301 && cipher_suite <= 0x1303) {
        return "TLS 1.3";
    }
    // TLS 1.2 cipher suites
    return "TLS 1.2";
}

const char* GetSignatureAlgorithmName(uint16_t sig_alg) {
    auto it = kSignatureAlgorithmNames.find(sig_alg);
    if (it != kSignatureAlgorithmNames.end()) {
        return it->second;
    }
    return "UNKNOWN";
}

const char* GetNamedGroupName(uint16_t named_group) {
    auto it = kNamedGroupNames.find(named_group);
    if (it != kNamedGroupNames.end()) {
        return it->second;
    }
    return "UNKNOWN";
}

}  // namespace tls_fingerprint
