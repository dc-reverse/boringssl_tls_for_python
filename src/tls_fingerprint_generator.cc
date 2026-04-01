// TLS Fingerprint Library - Standalone Generator Implementation

#include "tls_fingerprint/tls_fingerprint_generator.h"
#include <random>
#include <chrono>
#include <algorithm>

namespace tls_fingerprint {

namespace {

// GREASE values from Chromium
// These are reserved values that browsers use to test extension handling
const uint16_t kGreaseValues[] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
    0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
    0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA
};

// TLS extension types
enum TLSExtension {
    EXT_SERVER_NAME = 0x0000,
    EXT_STATUS_REQUEST = 0x0005,
    EXT_SUPPORTED_GROUPS = 0x000A,
    EXT_EC_POINT_FORMATS = 0x000B,
    EXT_SIGNATURE_ALGORITHMS = 0x000D,
    EXT_SCT = 0x0012,
    EXT_ALPN = 0x0010,
    EXT_EXTENDED_MASTER_SECRET = 0x0017,
    EXT_SIGNED_CERT_TIMESTAMP = 0x0012,
    EXT_KEY_SHARE = 0x0033,
    EXT_PSK_KEY_EXCHANGE_MODES = 0x002D,
    EXT_SUPPORTED_VERSIONS = 0x002B,
    EXT_COMPRESS_CERTIFICATE = 0x001B,
    EXT_APPLICATION_SETTINGS = 0x4469,
    EXT_ECH = 0xFE0D,
    EXT_RENEGOTIATION_INFO = 0xFF01,
};

// Write a 16-bit value in network byte order
void WriteU16BE(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 8));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Write a 24-bit value in network byte order
void WriteU24BE(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Write a 32-bit value in network byte order
void WriteU32BE(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Write a vector with length prefix
void WriteVector8(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data) {
    buf.push_back(static_cast<uint8_t>(data.size()));
    buf.insert(buf.end(), data.begin(), data.end());
}

void WriteVector16(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data) {
    WriteU16BE(buf, static_cast<uint16_t>(data.size()));
    buf.insert(buf.end(), data.begin(), data.end());
}

}  // namespace

TLSFingerprintGenerator::TLSFingerprintGenerator()
    : rng_(std::make_unique<std::mt19937>(
          std::chrono::steady_clock::now().time_since_epoch().count())) {
    // Initialize with Chrome desktop fingerprint by default
    config_ = BrowserFingerprints::ChromeDesktop();
    configured_ = true;
}

TLSFingerprintGenerator::~TLSFingerprintGenerator() = default;

void TLSFingerprintGenerator::SetConfig(const TLSFingerprintConfig& config) {
    config_ = config;
    configured_ = true;
}

std::mt19937& TLSFingerprintGenerator::GetRandomGenerator() {
    return *rng_;
}

std::vector<uint8_t> TLSFingerprintGenerator::GenerateClientHello(const std::string& hostname) {
    if (!configured_) {
        return {};
    }
    return BuildClientHello(hostname);
}

std::vector<uint8_t> TLSFingerprintGenerator::BuildClientHello(const std::string& hostname) {
    std::vector<uint8_t> hello;

    // Build ClientHello handshake message
    std::vector<uint8_t> handshake;

    // ClientHello type
    handshake.push_back(0x01);

    // Build ClientHello body (we'll prepend length later)
    std::vector<uint8_t> body;

    // Client version (legacy, use 0x0303 for TLS 1.2/1.3)
    body.push_back(0x03);
    body.push_back(0x03);

    // Random (32 bytes)
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (int i = 0; i < 32; i++) {
        body.push_back(dist(GetRandomGenerator()));
    }

    // Session ID (empty for TLS 1.3)
    body.push_back(0x00);

    // Cipher suites
    WriteU16BE(body, static_cast<uint16_t>(config_.cipher_suites.size() * 2));
    for (uint16_t cs : config_.cipher_suites) {
        WriteU16BE(body, cs);
    }

    // Compression methods
    body.push_back(0x01);  // Length
    body.push_back(0x00);  // null compression

    // Extensions
    std::vector<uint8_t> extensions = BuildExtensions(hostname);
    WriteU16BE(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    // Prepend ClientHello length (24-bit)
    WriteU24BE(handshake, static_cast<uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    // Wrap in TLS record layer
    hello.push_back(0x16);  // Content type: Handshake
    hello.push_back(0x03);  // Version major (TLS 1.0 in record layer)
    hello.push_back(0x01);  // Version minor

    // Record length
    WriteU16BE(hello, static_cast<uint16_t>(handshake.size()));
    hello.insert(hello.end(), handshake.begin(), handshake.end());

    return hello;
}

std::vector<uint8_t> TLSFingerprintGenerator::BuildExtensions(const std::string& hostname) {
    std::vector<uint8_t> extensions;

    // Build each extension
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> ext_list;

    // Server Name Indication
    {
        std::vector<uint8_t> sni;
        WriteU16BE(sni, static_cast<uint16_t>(hostname.size() + 3));  // List length
        sni.push_back(0x00);  // Host name type
        WriteU16BE(sni, static_cast<uint16_t>(hostname.size()));  // Name length
        sni.insert(sni.end(), hostname.begin(), hostname.end());
        ext_list.emplace_back(EXT_SERVER_NAME, sni);
    }

    // Extended Master Secret
    {
        ext_list.emplace_back(EXT_EXTENDED_MASTER_SECRET, std::vector<uint8_t>{});
    }

    // Renegotiation Info
    {
        ext_list.emplace_back(EXT_RENEGOTIATION_INFO, std::vector<uint8_t>{0x00});
    }

    // Supported Groups
    {
        std::vector<uint8_t> groups;
        WriteU16BE(groups, static_cast<uint16_t>(config_.named_groups.size() * 2));
        for (uint16_t g : config_.named_groups) {
            WriteU16BE(groups, g);
        }
        ext_list.emplace_back(EXT_SUPPORTED_GROUPS, groups);
    }

    // Signature Algorithms
    {
        std::vector<uint8_t> sig_algs;
        WriteU16BE(sig_algs, static_cast<uint16_t>(config_.signature_algorithms.size() * 2));
        for (uint16_t sa : config_.signature_algorithms) {
            WriteU16BE(sig_algs, sa);
        }
        ext_list.emplace_back(EXT_SIGNATURE_ALGORITHMS, sig_algs);
    }

    // ALPN
    {
        std::vector<uint8_t> alpn;
        std::vector<uint8_t> protocol_list;
        for (const auto& proto : config_.alpn_protocols) {
            protocol_list.push_back(static_cast<uint8_t>(proto.size()));
            protocol_list.insert(protocol_list.end(), proto.begin(), proto.end());
        }
        WriteU16BE(alpn, static_cast<uint16_t>(protocol_list.size()));
        alpn.insert(alpn.end(), protocol_list.begin(), protocol_list.end());
        ext_list.emplace_back(EXT_ALPN, alpn);
    }

    // Status Request (OCSP stapling)
    {
        std::vector<uint8_t> ocsp;
        ocsp.push_back(0x01);  // Status type: OCSP
        ocsp.push_back(0x00);  // Responder ID list length
        ocsp.push_back(0x00);
        ocsp.push_back(0x00);  // Request extensions length
        ocsp.push_back(0x00);
        ext_list.emplace_back(EXT_STATUS_REQUEST, ocsp);
    }

    // Signed Certificate Timestamp
    {
        ext_list.emplace_back(EXT_SCT, std::vector<uint8_t>{});
    }

    // Supported Versions (for TLS 1.3)
    {
        std::vector<uint8_t> versions;
        versions.push_back(0x02);  // Supported versions length
        versions.push_back(0x03);  // TLS 1.2
        versions.push_back(0x03);
        versions.push_back(0x03);  // TLS 1.3
        versions.push_back(0x04);
        ext_list.emplace_back(EXT_SUPPORTED_VERSIONS, versions);
    }

    // Key Share
    {
        std::vector<uint8_t> key_share;
        // For each named group, generate a placeholder key share
        for (uint16_t group : config_.named_groups) {
            std::vector<uint8_t> share_entry;
            WriteU16BE(share_entry, group);

            // Generate placeholder key share (32 bytes for x25519)
            int key_size = 32;  // Default for x25519
            if (group == 0x0017) key_size = 65;  // secp256r1
            else if (group == 0x0018) key_size = 97;  // secp384r1
            else if (group == 0x0019) key_size = 133;  // secp521r1

            std::uniform_int_distribution<uint8_t> dist(0, 255);
            std::vector<uint8_t> key_data(key_size);
            for (int i = 0; i < key_size; i++) {
                key_data[i] = dist(GetRandomGenerator());
            }

            WriteU16BE(share_entry, static_cast<uint16_t>(key_size));
            share_entry.insert(share_entry.end(), key_data.begin(), key_data.end());

            WriteU16BE(key_share, static_cast<uint16_t>(share_entry.size()));
            key_share.insert(key_share.end(), share_entry.begin(), share_entry.end());
        }
        ext_list.emplace_back(EXT_KEY_SHARE, key_share);
    }

    // PSK Key Exchange Modes (for TLS 1.3)
    {
        std::vector<uint8_t> psk_modes;
        psk_modes.push_back(0x02);  // Length
        psk_modes.push_back(0x01);  // PSK with (EC)DHE
        psk_modes.push_back(0x00);  // PSK only
        ext_list.emplace_back(EXT_PSK_KEY_EXCHANGE_MODES, psk_modes);
    }

    // Add GREASE extension if enabled
    if (config_.enable_grease) {
        std::uniform_int_distribution<size_t> grease_dist(0, 14);
        uint16_t grease_val = kGreaseValues[grease_dist(GetRandomGenerator())];

        // GREASE extension with random value
        std::vector<uint8_t> grease_data;
        WriteU16BE(grease_data, grease_val);
        ext_list.emplace_back(grease_val, grease_data);
    }

    // Permute extensions if enabled
    if (config_.permute_extensions) {
        std::shuffle(ext_list.begin(), ext_list.end(), GetRandomGenerator());
    }

    // Serialize extensions
    for (const auto& ext : ext_list) {
        WriteU16BE(extensions, ext.first);  // Extension type
        WriteU16BE(extensions, static_cast<uint16_t>(ext.second.size()));  // Extension length
        extensions.insert(extensions.end(), ext.second.begin(), ext.second.end());
    }

    return extensions;
}

bool TLSFingerprintGenerator::ConfigureSSLContext(struct ssl_ctx_st* ssl_ctx) {
    // This would configure BoringSSL SSL_CTX with the fingerprint settings
    // For now, return true as placeholder
    return true;
}

// TLSFingerprintAnalyzer implementation

std::string TLSFingerprintAnalyzer::IdentifyBrowser(const TLSFingerprintConfig& config) {
    // Simple browser identification based on cipher suite order

    // Chrome: First cipher suite is TLS_AES_128_GCM_SHA256, uses GREASE
    TLSFingerprintConfig chrome = BrowserFingerprints::ChromeDesktop();
    if (config.cipher_suites == chrome.cipher_suites &&
        config.enable_grease == chrome.enable_grease) {
        return "Chrome";
    }

    // Firefox: No GREASE, different signature algorithms
    TLSFingerprintConfig firefox = BrowserFingerprints::FirefoxDesktop();
    if (config.cipher_suites == firefox.cipher_suites &&
        config.enable_grease == firefox.enable_grease) {
        return "Firefox";
    }

    // Safari: Fewer cipher suites, no GREASE
    TLSFingerprintConfig safari = BrowserFingerprints::Safari();
    if (config.cipher_suites == safari.cipher_suites) {
        return "Safari";
    }

    return "Unknown";
}

TLSFingerprintConfig TLSFingerprintAnalyzer::ParseClientHello(const std::vector<uint8_t>& client_hello) {
    TLSFingerprintConfig config;

    // TODO: Implement ClientHello parsing
    // This would parse the raw bytes and extract the TLS fingerprint

    return config;
}

}  // namespace tls_fingerprint
