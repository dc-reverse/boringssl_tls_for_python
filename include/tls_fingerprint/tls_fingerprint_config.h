// TLS Fingerprint Library - Standalone Configuration
// Extracted and simplified from Chromium source code

#ifndef TLS_FINGERPRINT_CONFIG_H_
#define TLS_FINGERPRINT_CONFIG_H_

#include <vector>
#include <string>
#include <cstdint>
#include <map>

namespace tls_fingerprint {

// TLS version constants (matching Chromium)
enum TLSVersion {
    SSL_PROTOCOL_VERSION_TLS1_2 = 0x0303,
    SSL_PROTOCOL_VERSION_TLS1_3 = 0x0304,
};

// Cipher suite constants (common ones from Chromium)
enum CipherSuite {
    // TLS 1.3
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    // TLS 1.2 ECDHE
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
};

// Signature algorithm constants
enum SignatureAlgorithm {
    ECDSA_SECP256R1_SHA256 = 0x0403,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PKCS1_SHA256 = 0x0401,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    RSA_PKCS1_SHA512 = 0x0601,
};

// Named group constants
enum NamedGroup {
    X25519 = 0x001D,
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
};

// TLS Fingerprint Configuration
struct TLSFingerprintConfig {
    // TLS version range
    uint16_t version_min = SSL_PROTOCOL_VERSION_TLS1_2;
    uint16_t version_max = SSL_PROTOCOL_VERSION_TLS1_3;

    // Cipher suites (in priority order)
    std::vector<uint16_t> cipher_suites;

    // Signature algorithms
    std::vector<uint16_t> signature_algorithms;

    // Named groups (elliptic curves)
    std::vector<uint16_t> named_groups;

    // ALPN protocols
    std::vector<std::string> alpn_protocols;

    // Extension configuration
    bool permute_extensions = true;
    bool enable_grease = true;
    bool enable_ech = false;

    // ECH config list
    std::vector<uint8_t> ech_config_list;

    // Custom extensions
    std::map<uint16_t, std::vector<uint8_t>> custom_extensions;

    TLSFingerprintConfig() = default;
    TLSFingerprintConfig(const TLSFingerprintConfig&) = default;
    TLSFingerprintConfig(TLSFingerprintConfig&&) = default;
    TLSFingerprintConfig& operator=(const TLSFingerprintConfig&) = default;
    TLSFingerprintConfig& operator=(TLSFingerprintConfig&&) = default;
    ~TLSFingerprintConfig() = default;
};

// Browser fingerprint presets
// Based on real browser TLS fingerprints from Chromium
class BrowserFingerprints {
public:
    // Chrome Desktop (version 120+)
    static TLSFingerprintConfig ChromeDesktop();

    // Chrome Android
    static TLSFingerprintConfig ChromeAndroid();

    // Firefox Desktop
    static TLSFingerprintConfig FirefoxDesktop();

    // Safari
    static TLSFingerprintConfig Safari();

    // Edge (same as Chrome)
    static TLSFingerprintConfig Edge();

private:
    BrowserFingerprints() = delete;
};

// Cipher suite name lookup
const char* GetCipherSuiteName(uint16_t cipher_suite);
const char* GetCipherSuiteVersion(uint16_t cipher_suite);

// Signature algorithm name lookup
const char* GetSignatureAlgorithmName(uint16_t sig_alg);

// Named group name lookup
const char* GetNamedGroupName(uint16_t named_group);

}  // namespace tls_fingerprint

#endif  // TLS_FINGERPRINT_CONFIG_H_
