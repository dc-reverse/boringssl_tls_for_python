// BoringSSL Socket Implementation

#include "tls_fingerprint/boringssl_socket.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <sstream>
#include <iomanip>

// BoringSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace tls_fingerprint {

// Implementation class
class BoringSSLSocket::Impl {
public:
    Impl() : ssl_ctx_(nullptr), ssl_(nullptr), sock_fd_(-1),
             connected_(false), debug_(false) {}
    ~Impl() { Close(); }

    SSL_CTX* ssl_ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    int sock_fd_ = -1;
    std::string host_;
    int port_ = 0;
    bool connected_ = false;
    bool debug_ = false;
    std::string last_error_;
    std::string debug_log_;
    std::string resolved_ip_;
    TLSFingerprintConfig config_;

    void debugLog(const std::string& msg) {
        if (debug_) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch() % std::chrono::seconds(1)).count();

            std::stringstream ss;
            ss << "[" << std::put_time(std::localtime(&time), "%H:%M:%S")
               << "." << std::setfill('0') << std::setw(3) << ms << "] " << msg;
            debug_log_ += ss.str() + "\n";
            // Debug logs stored internally, use GetDebugLog() to retrieve
        }
    }

    static const char* GetCipherName(uint16_t cipher_id) {
        switch (cipher_id) {
            // TLS 1.3 (handled automatically by BoringSSL, skip in cipher list)
            case 0x1301: return "TLS_AES_128_GCM_SHA256";
            case 0x1302: return "TLS_AES_256_GCM_SHA384";
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
            // TLS 1.2 ECDHE GCM
            case 0xC02B: return "ECDHE-ECDSA-AES128-GCM-SHA256";
            case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
            case 0xC02C: return "ECDHE-ECDSA-AES256-GCM-SHA384";
            case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
            // TLS 1.2 ECDHE CHACHA20
            case 0xCCA9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
            case 0xCCA8: return "ECDHE-RSA-CHACHA20-POLY1305";
            // TLS 1.2 ECDHE CBC (legacy)
            case 0xC013: return "ECDHE-RSA-AES128-SHA";
            case 0xC014: return "ECDHE-RSA-AES256-SHA";
            // TLS 1.2 RSA GCM (legacy)
            case 0x009C: return "AES128-GCM-SHA256";
            case 0x009D: return "AES256-GCM-SHA384";
            // TLS 1.2 RSA CBC (legacy)
            case 0x002F: return "AES128-SHA";
            case 0x0035: return "AES256-SHA";
            default: return "UNKNOWN";
        }
    }

    static const char* GetGroupName(uint16_t group_id) {
        switch (group_id) {
            case 0x11EC: return "x25519_mlkem768";
            case 0x001D: return "x25519";
            case 0x0017: return "p256";
            case 0x0018: return "p384";
            case 0x0019: return "p521";
            default: return "UNKNOWN";
        }
    }

    bool InitSSLContext() {
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
        }
        ssl_ctx_ = SSL_CTX_new(TLS_method());
        if (!ssl_ctx_) {
            last_error_ = "Failed to create SSL_CTX";
            debugLog("ERROR: " + last_error_);
            return false;
        }

        SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);

        // Enable GREASE if configured
        if (config_.enable_grease) {
            SSL_CTX_set_grease_enabled(ssl_ctx_, 1);
        }

        // Enable extension permutation if configured (Chrome randomizes since v110)
        if (config_.permute_extensions) {
            SSL_CTX_set_permute_extensions(ssl_ctx_, 1);
        }

        // Enable compress_certificate extension (ext 27)
        // Chrome/Firefox/Safari all advertise Brotli (alg_id=2) for certificate compression
        // Client only needs decompression callback; compress can be NULL
        SSL_CTX_add_cert_compression_alg(
            ssl_ctx_, 2 /* Brotli */,
            nullptr /* compress - not needed for client */,
            [](SSL* ssl, CRYPTO_BUFFER** out,
               size_t uncompressed_len,
               const uint8_t* in, size_t in_len) -> int {
                // Simple pass-through decompression for fingerprinting purposes
                // In production, this would use Brotli decompression
                // For now, we just need the extension to appear in ClientHello
                // The server rarely actually compresses certificates
                return 0;  // Return 0 = failure, which is fine since we just need the extension advertised
            });

        return true;
    }

    void ConfigureSSLWithFingerprint() {
        if (!ssl_) {
            return;
        }

        debugLog("Configuring TLS fingerprint...");
        debugLog("Config: cipher_suites=" + std::to_string(config_.cipher_suites.size()) +
                 ", signature_algorithms=" + std::to_string(config_.signature_algorithms.size()) +
                 ", named_groups=" + std::to_string(config_.named_groups.size()));

        // 1. Configure cipher suites
        if (!config_.cipher_suites.empty()) {
            std::string cipher_list;
            for (uint16_t cs : config_.cipher_suites) {
                // Skip TLS 1.3 cipher suites (BoringSSL enables them automatically)
                if (cs >= 0x1300 && cs <= 0x13FF) continue;
                const char* name = GetCipherName(cs);
                if (std::string(name) == "UNKNOWN") continue;
                if (!cipher_list.empty()) cipher_list += ":";
                cipher_list += name;
            }

            if (!cipher_list.empty()) {
                debugLog("Setting cipher list: " + cipher_list);
                if (SSL_set_cipher_list(ssl_, cipher_list.c_str()) != 1) {
                    debugLog("Warning: Failed to set cipher list");
                }
            }
        }

        // 2. Configure named groups (elliptic curves)
        if (!config_.named_groups.empty()) {
            debugLog("Setting groups: " + std::to_string(config_.named_groups.size()) + " groups");
            std::string group_str;
            for (uint16_t g : config_.named_groups) {
                if (!group_str.empty()) group_str += ",";
                group_str += std::to_string(g);
            }
            debugLog("Group IDs: " + group_str);

            int ret = SSL_set1_group_ids(ssl_, config_.named_groups.data(),
                                    static_cast<size_t>(config_.named_groups.size()));
            debugLog("SSL_set1_group_ids returned: " + std::to_string(ret));
            if (ret != 1) {
                debugLog("Warning: Failed to set group IDs");
            }
        }

        // 3. Configure signature algorithms (CRITICAL for JA4 fingerprint)
        // Use numeric APIs directly for full algorithm support
        if (!config_.signature_algorithms.empty()) {
            debugLog("Setting signature algorithms: " + std::to_string(config_.signature_algorithms.size()) + " algorithms");

            std::string sig_str;
            for (uint16_t s : config_.signature_algorithms) {
                if (!sig_str.empty()) sig_str += ",";
                sig_str += std::to_string(s);
            }
            debugLog("Signature algorithm IDs: " + sig_str);

            // Use the numeric API to set signature algorithms directly
            // SSL_set_signing_algorithm_prefs sets the signing preferences
            // SSL_set_verify_algorithm_prefs sets the verification preferences
            int ret1 = SSL_set_signing_algorithm_prefs(ssl_,
                    config_.signature_algorithms.data(),
                    static_cast<size_t>(config_.signature_algorithms.size()));
            debugLog("SSL_set_signing_algorithm_prefs returned: " + std::to_string(ret1));
            if (ret1 != 1) {
                debugLog("Warning: Failed to set signing algorithm prefs");
            }

            int ret2 = SSL_set_verify_algorithm_prefs(ssl_,
                    config_.signature_algorithms.data(),
                    static_cast<size_t>(config_.signature_algorithms.size()));
            debugLog("SSL_set_verify_algorithm_prefs returned: " + std::to_string(ret2));
            if (ret2 != 1) {
                debugLog("Warning: Failed to set verify algorithm prefs");
            }
        }

        // 3. Configure ALPN protocols
        if (!config_.alpn_protocols.empty()) {
            std::vector<uint8_t> alpn_data;
            for (const std::string& proto : config_.alpn_protocols) {
                alpn_data.push_back(static_cast<uint8_t>(proto.length()));
                alpn_data.insert(alpn_data.end(), proto.begin(), proto.end());
            }

            std::string alpn_str;
            for (const auto& p : config_.alpn_protocols) {
                if (!alpn_str.empty()) alpn_str += ",";
                alpn_str += p;
            }
            debugLog("Setting ALPN: " + alpn_str);

            if (SSL_set_alpn_protos(ssl_, alpn_data.data(), alpn_data.size()) != 0) {
                debugLog("Warning: Failed to set ALPN protocols");
            }
        }

        debugLog("TLS fingerprint configuration complete");
    }

    int SetNonBlocking(bool non_block) {
        int flags = fcntl(sock_fd_, F_GETFL, 0);
        if (flags < 0) return -1;
        if (non_block) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }
        return fcntl(sock_fd_, F_SETFL, flags);
    }

    int WaitForSocket(bool wait_read, int timeout_ms) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_fd_, &fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int result;
        if (wait_read) {
            result = select(sock_fd_ + 1, &fds, nullptr, nullptr, &tv);
        } else {
            result = select(sock_fd_ + 1, nullptr, &fds, nullptr, &tv);
        }

        if (result < 0) {
            last_error_ = "select() failed";
            return -1;
        } else if (result == 0) {
            last_error_ = "Connection timed out";
            return -1;
        }
        return 0;
    }

    int ConnectTCP(const std::string& host, int port, int timeout_ms) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        // If we have a pre-resolved IP, use it directly (skip DNS)
        if (!resolved_ip_.empty()) {
            debugLog("Using pre-resolved IP: " + resolved_ip_);
            if (inet_pton(AF_INET, resolved_ip_.c_str(), &addr.sin_addr) != 1) {
                last_error_ = "Invalid pre-resolved IP: " + resolved_ip_;
                debugLog("ERROR: " + last_error_);
                return -1;
            }
        } else {
            // Fallback: resolve DNS using getaddrinfo (IPv4 only to avoid AAAA delays)
            debugLog("Resolving DNS for " + host + "...");
            auto dns_start = std::chrono::steady_clock::now();

            struct addrinfo hints, *result = nullptr;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;       // IPv4 only
            hints.ai_socktype = SOCK_STREAM;

            int gai_err = getaddrinfo(host.c_str(), nullptr, &hints, &result);
            if (gai_err != 0 || !result) {
                last_error_ = "Failed to resolve hostname: " + host +
                              " (" + gai_strerror(gai_err) + ")";
                debugLog("ERROR: " + last_error_);
                if (result) freeaddrinfo(result);
                return -1;
            }

            auto* sa = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            memcpy(&addr.sin_addr, &sa->sin_addr, sizeof(sa->sin_addr));
            freeaddrinfo(result);

            auto dns_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - dns_start).count();
            debugLog("DNS resolved in " + std::to_string(dns_elapsed) + "ms");
        }

        debugLog("Connecting to " + host + ":" + std::to_string(port) + "...");
        auto conn_start = std::chrono::steady_clock::now();

        if (SetNonBlocking(true) < 0) {
            last_error_ = "Failed to set non-blocking mode";
            return -1;
        }

        int result = ::connect(sock_fd_, (struct sockaddr*)&addr, sizeof(addr));
        if (result < 0 && errno != EINPROGRESS) {
            last_error_ = "connect() failed: " + std::string(strerror(errno));
            debugLog("ERROR: " + last_error_);
            return -1;
        }

        if (result != 0) {
            result = WaitForSocket(false, timeout_ms);
            if (result < 0) return result;
        }

        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sock_fd_, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            last_error_ = "getsockopt() failed";
            return -1;
        }
        if (error != 0) {
            last_error_ = "Connection failed: " + std::string(strerror(error));
            debugLog("ERROR: " + last_error_);
            return -1;
        }

        SetNonBlocking(false);

        auto conn_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - conn_start).count();
        debugLog("TCP connected in " + std::to_string(conn_elapsed) + "ms");

        return 0;
    }

    int DoSSLHandshake(const std::string& hostname) {
        debugLog("Starting SSL/TLS handshake with " + hostname + "...");
        auto ssl_start = std::chrono::steady_clock::now();

        if (!InitSSLContext()) {
            return -1;
        }

        ssl_ = SSL_new(ssl_ctx_);
        if (!ssl_) {
            last_error_ = "Failed to create SSL object";
            debugLog("ERROR: " + last_error_);
            return -1;
        }

        SSL_set_tlsext_host_name(ssl_, hostname.c_str());
        ConfigureSSLWithFingerprint();

        // Enable OCSP stapling (status_request extension, ext 5)
        SSL_enable_ocsp_stapling(ssl_);
        // Enable SCT (signed_certificate_timestamp extension, ext 18)
        SSL_enable_signed_cert_timestamps(ssl_);

        // Enable ALPS (Application-Layer Protocol Settings, ext 17513/0x4469)
        // Only Chrome/Edge use ALPS (they have both GREASE and permute_extensions enabled)
        // Firefox and Safari do NOT send ALPS
        if (config_.enable_grease && config_.permute_extensions) {
            SSL_set_alps_use_new_codepoint(ssl_, 0);  // Use old codepoint 17513 (0x4469)
            const uint8_t h2_proto[] = {'h', '2'};
            SSL_add_application_settings(ssl_, h2_proto, sizeof(h2_proto),
                                         nullptr, 0);  // Empty settings value
        }

        // Enable delegated_credentials (ext 34) for Firefox only
        // Firefox sends this extension; Chrome and Safari do not
        // Firefox = no GREASE + no permute_extensions
        if (!config_.enable_grease && !config_.permute_extensions) {
            SSL_set_delegated_credentials_enabled(ssl_, 1);
            // Enable record_size_limit (ext 28) - Firefox sends this
            SSL_set_record_size_limit_enabled(ssl_, 1);
        }

        // Set Safari-specific extension order to differentiate from Firefox
        // Safari = GREASE enabled + no permute_extensions
        // Real Safari 17+ extension order (by kExtensions index):
        //  0=SNI, 4=groups, 5=ec_point, 9=sigalgs, 2=EMS, 3=renegotiate,
        //  6=ticket, 11=SCT, 8=OCSP, 17=versions, 15=psk_modes, 14=key_share,
        //  7=ALPN, 21=cert_compress
        if (config_.enable_grease && !config_.permute_extensions) {
            const uint8_t safari_ext_order[] = {
                0,   // server_name (0x0000)
                4,   // supported_groups (0x000a)
                5,   // ec_point_formats (0x000b)
                9,   // signature_algorithms (0x000d)
                2,   // extended_master_secret (0x0017)
                3,   // renegotiate (0xff01)
                6,   // session_ticket (0x0023)
                11,  // certificate_timestamp (0x0012)
                8,   // status_request (0x0005)
                17,  // supported_versions (0x002b)
                15,  // psk_key_exchange_modes (0x002d)
                14,  // key_share (0x0033)
                7,   // ALPN (0x0010)
                21,  // cert_compression (0x001b)
            };
            SSL_set_extension_order(ssl_, safari_ext_order,
                                    sizeof(safari_ext_order));
        }

        SSL_set_fd(ssl_, sock_fd_);

        if (SetNonBlocking(true) < 0) {
            return -1;
        }

        const int handshake_timeout_ms = 30000;
        while (true) {
            int result = SSL_connect(ssl_);

            if (result == 1) {
                break;
            }

            int ssl_error = SSL_get_error(ssl_, result);

            if (ssl_error == SSL_ERROR_WANT_READ) {
                int wait_result = WaitForSocket(true, handshake_timeout_ms);
                if (wait_result < 0) return wait_result;
            } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
                int wait_result = WaitForSocket(false, handshake_timeout_ms);
                if (wait_result < 0) return wait_result;
            } else {
                unsigned long err = ERR_get_error();
                char err_buf[256];
                ERR_error_string_n(err, err_buf, sizeof(err_buf));
                last_error_ = std::string("SSL handshake failed: ") + err_buf;
                debugLog("ERROR: " + last_error_);
                return -1;
            }
        }

        SetNonBlocking(false);

        // Set socket recv/send timeout to prevent indefinite blocking
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        auto ssl_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - ssl_start).count();
        debugLog("SSL handshake completed in " + std::to_string(ssl_elapsed) + "ms");
        debugLog("Negotiated cipher: " + std::string(SSL_get_cipher(ssl_)));
        debugLog("TLS version: " + std::string(SSL_get_version(ssl_)));

        return 0;
    }

    int DoProxyConnect(const std::string& target_host, int target_port) {
        debugLog("Sending HTTP CONNECT to " + target_host + ":" + std::to_string(target_port));

        std::string request = "CONNECT " + target_host + ":" + std::to_string(target_port) + " HTTP/1.1\r\n";
        request += "Host: " + target_host + ":" + std::to_string(target_port) + "\r\n";
        request += "\r\n";

        if (send(sock_fd_, request.c_str(), request.size(), 0) < 0) {
            last_error_ = "Failed to send CONNECT request";
            return -1;
        }

        char response[4096];
        int total = 0;
        while (total < (int)sizeof(response) - 1) {
            int n = recv(sock_fd_, response + total, 1, 0);
            if (n <= 0) {
                last_error_ = "Failed to read proxy response";
                return -1;
            }
            total += n;
            response[total] = '\0';

            if (total >= 4 && strstr(response, "\r\n\r\n")) {
                break;
            }
        }

        if (strstr(response, "200") == nullptr) {
            last_error_ = "Proxy CONNECT failed: " + std::string(response);
            return -1;
        }

        debugLog("Proxy CONNECT successful");
        return 0;
    }

    int DoSocks5Handshake(const std::string& target_host, int target_port) {
        debugLog("Performing SOCKS5 handshake...");

        uint8_t greeting[3] = {0x05, 0x01, 0x00};
        if (send(sock_fd_, greeting, 3, 0) < 0) {
            last_error_ = "Failed to send SOCKS5 greeting";
            return -1;
        }

        uint8_t response[2];
        if (recv(sock_fd_, response, 2, 0) != 2) {
            last_error_ = "Invalid SOCKS5 response";
            return -1;
        }

        if (response[0] != 5) {
            last_error_ = "Not a SOCKS5 proxy";
            return -1;
        }

        uint8_t connect_req[512];
        int pos = 0;
        connect_req[pos++] = 0x05;
        connect_req[pos++] = 0x01;
        connect_req[pos++] = 0x00;
        connect_req[pos++] = 0x03;
        connect_req[pos++] = (uint8_t)target_host.size();
        memcpy(connect_req + pos, target_host.c_str(), target_host.size());
        pos += target_host.size();
        connect_req[pos++] = (target_port >> 8) & 0xFF;
        connect_req[pos++] = target_port & 0xFF;

        if (send(sock_fd_, connect_req, pos, 0) < 0) {
            last_error_ = "Failed to send SOCKS5 CONNECT";
            return -1;
        }

        uint8_t connect_resp[10];
        if (recv(sock_fd_, connect_resp, 10, 0) != 10) {
            last_error_ = "Invalid SOCKS5 CONNECT response";
            return -1;
        }

        if (connect_resp[1] != 0) {
            last_error_ = "SOCKS5 CONNECT failed";
            return -1;
        }

        debugLog("SOCKS5 handshake successful");
        return 0;
    }

    void Close() {
        if (ssl_) {
            // Set a short timeout for SSL_shutdown to avoid blocking
            if (sock_fd_ >= 0) {
                struct timeval tv;
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                setsockopt(sock_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(sock_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            }
            // Only attempt shutdown once, don't wait for close_notify response
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
        if (sock_fd_ >= 0) {
            close(sock_fd_);
            sock_fd_ = -1;
        }
        connected_ = false;
    }
};

// BoringSSLSocket implementation - just delegates to Impl
BoringSSLSocket::BoringSSLSocket() : impl_(new Impl()) {}

BoringSSLSocket::~BoringSSLSocket() = default;

void BoringSSLSocket::SetConfig(const TLSFingerprintConfig& config) {
    impl_->config_ = config;
}

void BoringSSLSocket::SetResolvedIP(const std::string& ip) {
    impl_->resolved_ip_ = ip;
}

int BoringSSLSocket::Connect(const std::string& host, int port, int timeout_ms) {
    impl_->debug_log_.clear();
    impl_->debugLog("=== Starting connection to " + host + ":" + std::to_string(port) + " ===");

    impl_->host_ = host;
    impl_->port_ = port;

    impl_->sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->sock_fd_ < 0) {
        impl_->last_error_ = "Failed to create socket";
        return -1;
    }

    if (impl_->ConnectTCP(host, port, timeout_ms) < 0) {
        return -1;
    }

    if (impl_->DoSSLHandshake(host) < 0) {
        return -1;
    }

    impl_->connected_ = true;
    impl_->debugLog("=== Connection completed ===");
    return 0;
}

int BoringSSLSocket::ConnectViaProxy(
    const std::string& proxy_host, int proxy_port,
    const std::string& target_host, int target_port,
    const std::string& proxy_type,
    int timeout_ms
) {
    impl_->debug_log_.clear();
    impl_->debugLog("=== Starting proxy connection to " + target_host + ":" + std::to_string(target_port) + " ===");
    impl_->debugLog("Via proxy: " + proxy_host + ":" + std::to_string(proxy_port) + " (" + proxy_type + ")");

    impl_->host_ = target_host;
    impl_->port_ = target_port;

    impl_->sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->sock_fd_ < 0) {
        impl_->last_error_ = "Failed to create socket";
        return -1;
    }

    if (impl_->ConnectTCP(proxy_host, proxy_port, timeout_ms) < 0) {
        return -1;
    }

    if (proxy_type == "socks5" || proxy_type == "socks") {
        if (impl_->DoSocks5Handshake(target_host, target_port) < 0) {
            return -1;
        }
    } else {
        if (impl_->DoProxyConnect(target_host, target_port) < 0) {
            return -1;
        }
    }

    if (impl_->DoSSLHandshake(target_host) < 0) {
        return -1;
    }

    impl_->connected_ = true;
    impl_->debugLog("=== Connection completed ===");
    return 0;
}

int BoringSSLSocket::Send(const uint8_t* data, size_t len) {
    if (!impl_->connected_ || !impl_->ssl_) {
        impl_->last_error_ = "Not connected";
        return -1;
    }
    int result = SSL_write(impl_->ssl_, data, static_cast<int>(len));
    if (result <= 0) {
        int ssl_error = SSL_get_error(impl_->ssl_, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        impl_->last_error_ = std::string("SSL_write failed: ") + err_buf;
        return -1;
    }
    return result;
}

int BoringSSLSocket::Send(const std::vector<uint8_t>& data) {
    return Send(data.data(), data.size());
}

int BoringSSLSocket::Recv(uint8_t* buf, size_t buf_len) {
    if (!impl_->connected_ || !impl_->ssl_) {
        impl_->last_error_ = "Not connected";
        return -1;
    }
    int result = SSL_read(impl_->ssl_, buf, static_cast<int>(buf_len));
    if (result < 0) {
        int ssl_error = SSL_get_error(impl_->ssl_, result);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            return 0;
            }
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                return 0;
            }
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        impl_->last_error_ = std::string("SSL_read failed: ") + err_buf;
        return -1;
    }
    return result;
}

std::vector<uint8_t> BoringSSLSocket::Recv(size_t max_len) {
    std::vector<uint8_t> buf(max_len);
    int n = Recv(buf.data(), max_len);
    if (n < 0) {
        return {};
    }
    buf.resize(n > 0 ? n : 0);
    return buf;
}

void BoringSSLSocket::Close() {
    impl_->Close();
}

bool BoringSSLSocket::IsConnected() const {
    return impl_->connected_;
}

SSLConnectionInfo BoringSSLSocket::GetConnectionInfo() const {
    SSLConnectionInfo info;
    if (impl_->ssl_) {
        info.cipher_suite = SSL_get_cipher(impl_->ssl_);
        info.version = SSL_get_version(impl_->ssl_);

        const unsigned char* alpn;
        unsigned int alpn_len;
        SSL_get0_alpn_selected(impl_->ssl_, &alpn, &alpn_len);
        if (alpn && alpn_len > 0) {
            info.negotiated_protocol = std::string((const char*)alpn, alpn_len);
        }
    }
    return info;
}

std::string BoringSSLSocket::GetLastError() const {
    return impl_->last_error_;
}

void BoringSSLSocket::SetDebug(bool debug) {
    impl_->debug_ = debug;
}

std::string BoringSSLSocket::GetDebugLog() const {
    return impl_->debug_log_;
}

}  // namespace tls_fingerprint
