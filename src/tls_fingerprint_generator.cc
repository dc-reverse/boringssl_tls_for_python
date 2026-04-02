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
    EXT_PADDING = 0x0015,
    EXT_ALPN = 0x0010,
    EXT_SCT = 0x0012,
    EXT_EXTENDED_MASTER_SECRET = 0x0017,
    EXT_COMPRESS_CERTIFICATE = 0x001B,
    EXT_SESSION_TICKET = 0x0023,
    EXT_SUPPORTED_VERSIONS = 0x002B,
    EXT_PSK_KEY_EXCHANGE_MODES = 0x002D,
    EXT_KEY_SHARE = 0x0033,
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

    // Session ID (32 bytes for TLS 1.3 middlebox compatibility, RFC 8446 D.4)
    body.push_back(0x20);  // 32 bytes length
    for (int i = 0; i < 32; i++) {
        body.push_back(dist(GetRandomGenerator()));
    }

    // Cipher suites (with optional GREASE at the beginning)
    if (config_.enable_grease) {
        std::uniform_int_distribution<size_t> grease_dist(0, 14);
        uint16_t grease_cs = kGreaseValues[grease_dist(GetRandomGenerator())];
        WriteU16BE(body, static_cast<uint16_t>((config_.cipher_suites.size() + 1) * 2));
        WriteU16BE(body, grease_cs);
    } else {
        WriteU16BE(body, static_cast<uint16_t>(config_.cipher_suites.size() * 2));
    }
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

    // EC Point Formats (Chrome sends 3 formats)
    {
        std::vector<uint8_t> ec_pf;
        ec_pf.push_back(0x03);  // Length: 3 formats
        ec_pf.push_back(0x00);  // uncompressed
        ec_pf.push_back(0x01);  // ansiX962_compressed_prime
        ec_pf.push_back(0x02);  // ansiX962_compressed_char2
        ext_list.emplace_back(EXT_EC_POINT_FORMATS, ec_pf);
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

    // Session Ticket (Chrome sends empty session ticket)
    {
        ext_list.emplace_back(EXT_SESSION_TICKET, std::vector<uint8_t>{});
    }

    // Compress Certificate (Chrome advertises Brotli = algorithm 2)
    {
        std::vector<uint8_t> compress;
        compress.push_back(0x02);  // algorithms list length (2 bytes for 1 algorithm)
        compress.push_back(0x00);
        compress.push_back(0x02);  // Brotli = 0x0002
        ext_list.emplace_back(EXT_COMPRESS_CERTIFICATE, compress);
    }

    // Application Settings (ALPS) - Chrome uses this for HTTP/2
    {
        std::vector<uint8_t> alps;
        // Protocol list (same format as ALPN)
        std::vector<uint8_t> alps_protocols;
        std::string h2_proto = "h2";
        alps_protocols.push_back(static_cast<uint8_t>(h2_proto.size()));
        alps_protocols.insert(alps_protocols.end(), h2_proto.begin(), h2_proto.end());
        WriteU16BE(alps, static_cast<uint16_t>(alps_protocols.size()));
        alps.insert(alps.end(), alps_protocols.begin(), alps_protocols.end());
        ext_list.emplace_back(EXT_APPLICATION_SETTINGS, alps);
    }

    // Supported Versions (for TLS 1.3, with optional GREASE version)
    {
        std::vector<uint8_t> versions;
        if (config_.enable_grease) {
            std::uniform_int_distribution<size_t> grease_dist(0, 14);
            uint16_t grease_ver = kGreaseValues[grease_dist(GetRandomGenerator())];
            versions.push_back(0x05);  // 5 bytes = GREASE + TLS 1.3 + TLS 1.2
            versions.push_back(static_cast<uint8_t>(grease_ver >> 8));
            versions.push_back(static_cast<uint8_t>(grease_ver & 0xFF));
        } else {
            versions.push_back(0x03);  // 3 bytes = TLS 1.3 + TLS 1.2 (Firefox)
        }
        versions.push_back(0x03);  // TLS 1.3 (preferred)
        versions.push_back(0x04);
        versions.push_back(0x03);  // TLS 1.2
        versions.push_back(0x03);
        ext_list.emplace_back(EXT_SUPPORTED_VERSIONS, versions);
    }

    // Key Share - Chrome only sends shares for X25519MLKEM768 and X25519
    {
        std::vector<uint8_t> key_share;
        std::vector<uint8_t> key_share_entries;

        for (uint16_t group : config_.named_groups) {
            // Chrome only sends key shares for the first 2 groups
            // (x25519_mlkem768 + x25519), not for secp256r1/384r1/521r1
            if (group == 0x0017 || group == 0x0018 || group == 0x0019) {
                continue;  // Skip NIST curves in key share
            }

            std::vector<uint8_t> share_entry;
            WriteU16BE(share_entry, group);

            int key_size = 32;  // Default for x25519
            if (group == 0x11EC) key_size = 1120;  // x25519_mlkem768: 1120 bytes

            std::uniform_int_distribution<uint8_t> dist(0, 255);
            std::vector<uint8_t> key_data(key_size);
            for (int i = 0; i < key_size; i++) {
                key_data[i] = dist(GetRandomGenerator());
            }

            WriteU16BE(share_entry, static_cast<uint16_t>(key_size));
            share_entry.insert(share_entry.end(), key_data.begin(), key_data.end());

            key_share_entries.insert(key_share_entries.end(), share_entry.begin(), share_entry.end());
        }

        WriteU16BE(key_share, static_cast<uint16_t>(key_share_entries.size()));
        key_share.insert(key_share.end(), key_share_entries.begin(), key_share_entries.end());
        ext_list.emplace_back(EXT_KEY_SHARE, key_share);
    }

    // PSK Key Exchange Modes (for TLS 1.3)
    // Chrome sends only psk_dhe_ke (1)
    {
        std::vector<uint8_t> psk_modes;
        psk_modes.push_back(0x01);  // Length: 1 mode
        psk_modes.push_back(0x01);  // PSK with (EC)DHE only
        ext_list.emplace_back(EXT_PSK_KEY_EXCHANGE_MODES, psk_modes);
    }

    // Add GREASE extensions if enabled
    if (config_.enable_grease) {
        std::uniform_int_distribution<size_t> grease_dist(0, 14);

        // GREASE extension at the beginning
        uint16_t grease_val1 = kGreaseValues[grease_dist(GetRandomGenerator())];
        ext_list.insert(ext_list.begin(),
            std::make_pair(grease_val1, std::vector<uint8_t>{0x00}));

        // GREASE extension near the end
        uint16_t grease_val2 = kGreaseValues[grease_dist(GetRandomGenerator())];
        while (grease_val2 == grease_val1) {
            grease_val2 = kGreaseValues[grease_dist(GetRandomGenerator())];
        }
        ext_list.emplace_back(grease_val2, std::vector<uint8_t>{0x00});
    }

    // Permute extensions if enabled (Chrome randomizes since v110)
    if (config_.permute_extensions) {
        std::shuffle(ext_list.begin(), ext_list.end(), GetRandomGenerator());
    }

    // Calculate current ClientHello size and add padding if needed (Chrome behavior)
    // Chrome pads the ClientHello to 512 bytes if it would be between 256-511 bytes
    {
        // Estimate total size: record header(5) + handshake header(4) + body_so_far + extensions
        size_t ext_size = 0;
        for (const auto& ext : ext_list) {
            ext_size += 4 + ext.second.size();  // 2 (type) + 2 (length) + data
        }
        // body: version(2) + random(32) + session_id(33) + cipher_suites(2+n) + compression(2) + ext_len(2)
        size_t body_size = 2 + 32 + 33 + 2 + config_.cipher_suites.size() * 2 + 2 + 2 + ext_size;
        if (config_.enable_grease) body_size += 2;  // GREASE cipher suite
        size_t total_size = 5 + 4 + body_size;  // record header + handshake header

        if (total_size > 256 && total_size < 512) {
            size_t padding_needed = 512 - total_size - 4;  // 4 for padding extension header
            if (padding_needed > 0 && padding_needed < 65536) {
                std::vector<uint8_t> padding_data(padding_needed, 0x00);
                ext_list.emplace_back(EXT_PADDING, padding_data);
            }
        }
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
