// BoringSSL Socket Wrapper for Python
// Provides SSL socket using BoringSSL with custom TLS fingerprints

#ifndef TLS_FINGERPRINT_BORINGSSL_SOCKET_H_
#define TLS_FINGERPRINT_BORINGSSL_SOCKET_H_

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

// Forward declarations for BoringSSL types
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_st X509;

#include "tls_fingerprint/tls_fingerprint_config.h"

namespace tls_fingerprint {

// SSL connection information
struct SSLConnectionInfo {
    std::string negotiated_protocol;
    std::string cipher_suite;
    std::string version;
    bool peer_cert_verified = false;
    std::vector<uint8_t> peer_certificate;
};

// BoringSSL Socket implementation
class BoringSSLSocket {
public:
    BoringSSLSocket();
    ~BoringSSLSocket();

    // Delete copy constructor and assignment
    BoringSSLSocket(const BoringSSLSocket&) = delete;
    BoringSSLSocket& operator=(const BoringSSLSocket&) = delete;

    // Set TLS fingerprint configuration
    void SetConfig(const TLSFingerprintConfig& config);

    // Set pre-resolved IP address to skip DNS in Connect()
    // The host parameter in Connect() will still be used for TLS SNI
    void SetResolvedIP(const std::string& ip);

    // Connect to host:port directly
    // Returns 0 on success, negative on error
    int Connect(const std::string& host, int port, int timeout_ms = 30000);

    // Connect via proxy
    int ConnectViaProxy(
        const std::string& proxy_host,
        int proxy_port,
        const std::string& target_host,
        int target_port,
        const std::string& proxy_type = "http",
        int timeout_ms = 30000
    );

    // Send data
    // Returns number of bytes sent, or negative on error
    int Send(const uint8_t* data, size_t len);
    int Send(const std::vector<uint8_t>& data);

    // Receive data
    // Returns number of bytes received, or negative on error
    int Recv(uint8_t* buf, size_t buf_len);
    std::vector<uint8_t> Recv(size_t max_len = 8192);

    // Close connection
    void Close();

    // Check if connected
    bool IsConnected() const;

    // Get connection info
    SSLConnectionInfo GetConnectionInfo() const;

    // Get last error message
    std::string GetLastError() const;

    // Set debug mode
    void SetDebug(bool debug);

    // Get debug log
    std::string GetDebugLog() const;

private:
    // Internal implementation
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tls_fingerprint

#endif  // TLS_FINGERPRINT_BORINGSSL_SOCKET_H_
