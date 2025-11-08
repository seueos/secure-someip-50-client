#ifndef EXPERIMENT_CRYPTO_CONFIG_HPP
#define EXPERIMENT_CRYPTO_CONFIG_HPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace experiment {
namespace config {

// 6가지 보안 카테고리를 정의하는 구조체
struct crypto_suite_config {
    std::string name;
    std::string description;

    // 6가지 보안 카테고리
    std::string key_exchange;      // ECDHE-P256, ECDHE-P384, X25519 등
    std::string key_derivation;    // HKDF-SHA256, HKDF-SHA384 등
    std::string hash;              // SHA256, SHA384, SHA3-256 등
    std::string data_protection;   // AES256-GCM, AES128-GCM, ChaCha20-Poly1305 등
    std::string message_auth;      // HMAC-SHA256, Poly1305 등
    std::string signature;         // ECDSA-P256, ECDSA-P384, Ed25519, RSA-PSS 등

    // JSON 직렬화 지원
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(crypto_suite_config,
        name, description,
        key_exchange, key_derivation, hash,
        data_protection, message_auth, signature)
};

// 전체 설정 구조체
struct plugin_config {
    std::string name;
    std::string path;
    bool enabled = true;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(plugin_config, name, path, enabled)
};

struct crypto_config {
    std::string active_suite;
    bool enable_experiment = true;
    std::vector<crypto_suite_config> suites;
    std::vector<plugin_config> plugins;

    // JSON 직렬화 지원
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(crypto_config,
        active_suite, enable_experiment, suites, plugins)
};

// 설정 로더 클래스
class crypto_config_loader {
public:
    static crypto_config load_from_file(const std::string& filepath);
    static void save_to_file(const std::string& filepath, const crypto_config& config);
    static crypto_config get_default_config();
};

} // namespace config
} // namespace experiment

#endif // EXPERIMENT_CRYPTO_CONFIG_HPP
