#include "../../include/config/crypto_config.hpp"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

namespace experiment {
namespace config {

crypto_config crypto_config_loader::load_from_file(const std::string& filepath) {
    try {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file: " << filepath << std::endl;
            return get_default_config();
        }

        nlohmann::json j;
        file >> j;
        return j.get<crypto_config>();
    } catch (const std::exception& e) {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        return get_default_config();
    }
}

void crypto_config_loader::save_to_file(const std::string& filepath, const crypto_config& config) {
    try {
        std::ofstream file(filepath);
        if (!file.is_open()) {
            std::cerr << "Failed to open config file for writing: " << filepath << std::endl;
            return;
        }

        nlohmann::json j = config;
        file << j.dump(4); // pretty print with 4 spaces
    } catch (const std::exception& e) {
        std::cerr << "Error saving config: " << e.what() << std::endl;
    }
}

crypto_config crypto_config_loader::get_default_config() {
    crypto_config config;
    config.active_suite = "default_tls13";
    config.enable_experiment = true;

    // 기본 TLS 1.3 스타일 스위트
    crypto_suite_config default_suite;
    default_suite.name = "default_tls13";
    default_suite.description = "Default TLS 1.3 style crypto suite";
    default_suite.key_exchange = "ECDHE-P256";
    default_suite.key_derivation = "HKDF-SHA256";
    default_suite.hash = "SHA256";
    default_suite.data_protection = "AES256-GCM";
    default_suite.message_auth = "HMAC-SHA256";
    default_suite.signature = "ECDSA-P256";

    // 대안 스위트들
    crypto_suite_config alt_suite1;
    alt_suite1.name = "alt_aes128";
    alt_suite1.description = "Alternative suite with AES128";
    alt_suite1.key_exchange = "ECDHE-P256";
    alt_suite1.key_derivation = "HKDF-SHA256";
    alt_suite1.hash = "SHA256";
    alt_suite1.data_protection = "AES128-GCM";
    alt_suite1.message_auth = "HMAC-SHA256";
    alt_suite1.signature = "ECDSA-P256";

    crypto_suite_config alt_suite2;
    alt_suite2.name = "alt_chacha20";
    alt_suite2.description = "Suite with ChaCha20-Poly1305";
    alt_suite2.key_exchange = "ECDHE-P256";
    alt_suite2.key_derivation = "HKDF-SHA256";
    alt_suite2.hash = "SHA256";
    alt_suite2.data_protection = "ChaCha20-Poly1305";
    alt_suite2.message_auth = "HMAC-SHA256";
    alt_suite2.signature = "Ed25519";

    config.suites = {default_suite, alt_suite1, alt_suite2};
    return config;
}

} // namespace config
} // namespace experiment
