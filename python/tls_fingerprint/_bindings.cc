// Python bindings for TLS Fingerprint Library
// Using pybind11

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include "tls_fingerprint/tls_fingerprint_config.h"
#include "tls_fingerprint/tls_fingerprint_generator.h"
#include "tls_fingerprint/boringssl_socket.h"

namespace py = pybind11;

PYBIND11_MODULE(_tls_fingerprint, m) {
    m.doc() = "Chromium-based TLS Fingerprint Library for Python";

    // Module version
    m.attr("__version__") = "1.0.0";

    // TLSFingerprintConfig
    py::class_<tls_fingerprint::TLSFingerprintConfig>(m, "TLSFingerprintConfig")
        .def(py::init<>())
        .def_readwrite("version_min", &tls_fingerprint::TLSFingerprintConfig::version_min,
                      "Minimum TLS version (0x0303=TLS1.2, 0x0304=TLS1.3)")
        .def_readwrite("version_max", &tls_fingerprint::TLSFingerprintConfig::version_max,
                      "Maximum TLS version")
        .def_readwrite("cipher_suites", &tls_fingerprint::TLSFingerprintConfig::cipher_suites,
                      "List of cipher suite IDs in priority order")
        .def_readwrite("signature_algorithms", &tls_fingerprint::TLSFingerprintConfig::signature_algorithms,
                      "List of signature algorithm IDs")
        .def_readwrite("named_groups", &tls_fingerprint::TLSFingerprintConfig::named_groups,
                      "List of named group IDs (elliptic curves)")
        .def_readwrite("alpn_protocols", &tls_fingerprint::TLSFingerprintConfig::alpn_protocols,
                      "List of ALPN protocol strings")
        .def_readwrite("permute_extensions", &tls_fingerprint::TLSFingerprintConfig::permute_extensions,
                      "Whether to randomly permute extension order")
        .def_readwrite("enable_grease", &tls_fingerprint::TLSFingerprintConfig::enable_grease,
                      "Whether to add GREASE extensions")
        .def_readwrite("enable_ech", &tls_fingerprint::TLSFingerprintConfig::enable_ech,
                      "Whether to enable Encrypted Client Hello")
        .def_readwrite("ech_config_list", &tls_fingerprint::TLSFingerprintConfig::ech_config_list,
                      "ECH configuration bytes")
        .def("__repr__", [](const tls_fingerprint::TLSFingerprintConfig& c) {
            return "<TLSFingerprintConfig cipher_suites=" + std::to_string(c.cipher_suites.size()) +
                   " signature_algorithms=" + std::to_string(c.signature_algorithms.size()) +
                   " named_groups=" + std::to_string(c.named_groups.size()) + ">";
        });

    // TLSFingerprintGenerator
    py::class_<tls_fingerprint::TLSFingerprintGenerator>(m, "TLSFingerprintGenerator")
        .def(py::init<>())
        .def("set_config", &tls_fingerprint::TLSFingerprintGenerator::SetConfig,
             py::arg("config"),
             "Set the fingerprint configuration")
        .def("get_config", &tls_fingerprint::TLSFingerprintGenerator::GetConfig,
             py::return_value_policy::reference_internal,
             "Get the current configuration")
        .def("generate_client_hello", &tls_fingerprint::TLSFingerprintGenerator::GenerateClientHello,
             py::arg("hostname"),
             "Generate ClientHello bytes for the given hostname");

    // BrowserFingerprints - static methods
    py::class_<tls_fingerprint::BrowserFingerprints>(m, "BrowserFingerprints")
        .def_static("chrome_desktop", &tls_fingerprint::BrowserFingerprints::ChromeDesktop,
                   "Get Chrome desktop browser fingerprint")
        .def_static("chrome_android", &tls_fingerprint::BrowserFingerprints::ChromeAndroid,
                   "Get Chrome Android browser fingerprint")
        .def_static("firefox_desktop", &tls_fingerprint::BrowserFingerprints::FirefoxDesktop,
                   "Get Firefox desktop browser fingerprint")
        .def_static("safari", &tls_fingerprint::BrowserFingerprints::Safari,
                   "Get Safari browser fingerprint")
        .def_static("edge", &tls_fingerprint::BrowserFingerprints::Edge,
                   "Get Edge browser fingerprint");

    // TLSFingerprintAnalyzer - static methods
    py::class_<tls_fingerprint::TLSFingerprintAnalyzer>(m, "TLSFingerprintAnalyzer")
        .def_static("identify_browser", &tls_fingerprint::TLSFingerprintAnalyzer::IdentifyBrowser,
                   py::arg("config"),
                   "Identify browser type from fingerprint configuration")
        .def_static("parse_client_hello", &tls_fingerprint::TLSFingerprintAnalyzer::ParseClientHello,
                   py::arg("client_hello"),
                   "Parse ClientHello bytes and extract configuration");

    // Utility functions
    m.def("get_cipher_suite_name", &tls_fingerprint::GetCipherSuiteName,
          py::arg("cipher_suite"),
          "Get human-readable name for cipher suite ID");

    m.def("get_cipher_suite_version", &tls_fingerprint::GetCipherSuiteVersion,
          py::arg("cipher_suite"),
          "Get TLS version for cipher suite");

    m.def("get_signature_algorithm_name", &tls_fingerprint::GetSignatureAlgorithmName,
          py::arg("sig_alg"),
          "Get human-readable name for signature algorithm ID");

    m.def("get_named_group_name", &tls_fingerprint::GetNamedGroupName,
          py::arg("named_group"),
          "Get human-readable name for named group ID");

    // Constants - cast enum to int
    m.attr("TLS_AES_128_GCM_SHA256") = static_cast<int>(tls_fingerprint::TLS_AES_128_GCM_SHA256);
    m.attr("TLS_AES_256_GCM_SHA384") = static_cast<int>(tls_fingerprint::TLS_AES_256_GCM_SHA384);
    m.attr("TLS_CHACHA20_POLY1305_SHA256") = static_cast<int>(tls_fingerprint::TLS_CHACHA20_POLY1305_SHA256);
    m.attr("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") = static_cast<int>(tls_fingerprint::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    m.attr("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") = static_cast<int>(tls_fingerprint::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

    m.attr("ECDSA_SECP256R1_SHA256") = static_cast<int>(tls_fingerprint::ECDSA_SECP256R1_SHA256);
    m.attr("RSA_PSS_RSAE_SHA256") = static_cast<int>(tls_fingerprint::RSA_PSS_RSAE_SHA256);

    m.attr("X25519") = static_cast<int>(tls_fingerprint::X25519);
    m.attr("SECP256R1") = static_cast<int>(tls_fingerprint::SECP256R1);
    m.attr("SECP384R1") = static_cast<int>(tls_fingerprint::SECP384R1);

    // SSLConnectionInfo
    py::class_<tls_fingerprint::SSLConnectionInfo>(m, "SSLConnectionInfo")
        .def_readonly("negotiated_protocol", &tls_fingerprint::SSLConnectionInfo::negotiated_protocol,
                      "Negotiated ALPN protocol")
        .def_readonly("cipher_suite", &tls_fingerprint::SSLConnectionInfo::cipher_suite,
                      "Negotiated cipher suite")
        .def_readonly("version", &tls_fingerprint::SSLConnectionInfo::version,
                      "TLS version")
        .def_readonly("peer_cert_verified", &tls_fingerprint::SSLConnectionInfo::peer_cert_verified,
                      "Whether peer certificate was verified")
        .def_readonly("peer_certificate", &tls_fingerprint::SSLConnectionInfo::peer_certificate,
                      "Peer certificate in DER format")
        .def("__repr__", [](const tls_fingerprint::SSLConnectionInfo& info) {
            return "<SSLConnectionInfo protocol=" + info.negotiated_protocol +
                   " cipher=" + info.cipher_suite + " version=" + info.version + ">";
        });

    // BoringSSLSocket
    py::class_<tls_fingerprint::BoringSSLSocket>(m, "BoringSSLSocket")
        .def(py::init<>())
        .def("set_config", &tls_fingerprint::BoringSSLSocket::SetConfig,
             py::arg("config"),
             "Set the TLS fingerprint configuration")
        .def("connect", &tls_fingerprint::BoringSSLSocket::Connect,
             py::arg("host"),
             py::arg("port"),
             py::arg("timeout_ms") = 30000,
             "Connect to host:port using TLS")
        .def("connect_via_proxy", &tls_fingerprint::BoringSSLSocket::ConnectViaProxy,
             py::arg("proxy_host"),
             py::arg("proxy_port"),
             py::arg("target_host"),
             py::arg("target_port"),
             py::arg("proxy_type") = "http",
             py::arg("timeout_ms") = 30000,
             "Connect via HTTP/SOCKS5 proxy")
        .def("send", [](tls_fingerprint::BoringSSLSocket& self, py::bytes data) {
                 std::string str = data;
                 std::vector<uint8_t> vec(str.begin(), str.end());
                 return self.Send(vec);
             },
             py::arg("data"),
             "Send bytes over TLS connection")
        .def("recv", [](tls_fingerprint::BoringSSLSocket& self, size_t max_len) {
                 std::vector<uint8_t> data = self.Recv(max_len);
                 return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
             },
             py::arg("max_len") = 8192,
             "Receive bytes from TLS connection")
        .def("close", &tls_fingerprint::BoringSSLSocket::Close,
             "Close the connection")
        .def("is_connected", &tls_fingerprint::BoringSSLSocket::IsConnected,
             "Check if connected")
        .def("get_connection_info", &tls_fingerprint::BoringSSLSocket::GetConnectionInfo,
             "Get SSL connection info")
        .def("get_last_error", &tls_fingerprint::BoringSSLSocket::GetLastError,
             "Get last error message")
        .def("set_debug", &tls_fingerprint::BoringSSLSocket::SetDebug,
             py::arg("debug"),
             "Enable/disable debug logging")
        .def("get_debug_log", &tls_fingerprint::BoringSSLSocket::GetDebugLog,
             "Get debug log output");
}
