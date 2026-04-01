// TLS Fingerprint Library - Standalone Generator
// Simplified ClientHello generator

#ifndef TLS_FINGERPRINT_GENERATOR_H_
#define TLS_FINGERPRINT_GENERATOR_H_

#include "tls_fingerprint/tls_fingerprint_config.h"
#include <cstdint>
#include <memory>
#include <string>
#include <random>

namespace tls_fingerprint {

// Forward declarations for BoringSSL
struct ssl_ctx_st;
struct ssl_st;

// TLS Fingerprint Generator
// Generates TLS ClientHello messages with specific fingerprints
class TLSFingerprintGenerator {
public:
    TLSFingerprintGenerator();
    ~TLSFingerprintGenerator();

    // Non-copyable
    TLSFingerprintGenerator(const TLSFingerprintGenerator&) = delete;
    TLSFingerprintGenerator& operator=(const TLSFingerprintGenerator&) = delete;

    // Set the fingerprint configuration
    void SetConfig(const TLSFingerprintConfig& config);

    // Get the current configuration
    const TLSFingerprintConfig& GetConfig() const { return config_; }

    // Generate ClientHello data (raw bytes)
    // This generates a simplified ClientHello that can be used for fingerprinting
    std::vector<uint8_t> GenerateClientHello(const std::string& hostname);

    // Configure an external SSL_CTX with the fingerprint settings
    // This is for integration with actual TLS libraries
    bool ConfigureSSLContext(struct ssl_ctx_st* ssl_ctx);

private:
    // Build ClientHello handshake message
    std::vector<uint8_t> BuildClientHello(const std::string& hostname);

    // Build ClientHello extensions
    std::vector<uint8_t> BuildExtensions(const std::string& hostname);

    // Random number generation
    std::mt19937& GetRandomGenerator();

    TLSFingerprintConfig config_;
    std::unique_ptr<std::mt19937> rng_;
    bool configured_ = false;
};

// TLS Fingerprint Analyzer
// Utility class for analyzing TLS fingerprints
class TLSFingerprintAnalyzer {
public:
    // Identify browser type from fingerprint configuration
    static std::string IdentifyBrowser(const TLSFingerprintConfig& config);

    // Parse a ClientHello message and extract configuration
    static TLSFingerprintConfig ParseClientHello(const std::vector<uint8_t>& client_hello);

private:
    TLSFingerprintAnalyzer() = delete;
};

}  // namespace tls_fingerprint

#endif  // TLS_FINGERPRINT_GENERATOR_H_
