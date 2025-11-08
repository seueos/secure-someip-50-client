#include "../include/config/crypto_config.hpp"
#include "../include/crypto/crypto_factory.hpp"
#include <iostream>
#include <cassert>

int main() {
    std::cout << "Testing crypto experiment framework..." << std::endl;

    // 1. 기본 설정 로드 테스트
    auto default_config = experiment::config::crypto_config_loader::get_default_config();
    std::cout << "Default config has " << default_config.suites.size() << " suites" << std::endl;
    assert(default_config.suites.size() == 3);

    // 2. 파일에서 설정 로드 테스트
    bool loaded = experiment::crypto::crypto_factory::get_instance().load_config("../config/crypto_suites.json");
    assert(loaded);

    // 3. 활성 스위트 확인
    auto active_suite = experiment::crypto::crypto_factory::get_instance().get_active_suite();
    assert(active_suite != nullptr);
    std::cout << "Active suite: " << active_suite->get_config().name << std::endl;

    // 4. 각 카테고리 인터페이스 확인
    auto key_exchange = active_suite->get_key_exchange();
    auto key_derivation = active_suite->get_key_derivation();
    auto hash = active_suite->get_hash();
    auto data_protection = active_suite->get_data_protection();
    auto message_auth = active_suite->get_message_auth();
    auto signature = active_suite->get_signature();

    assert(key_exchange->is_supported());
    assert(key_derivation->is_supported());
    assert(hash->is_supported());
    assert(data_protection->is_supported());
    assert(message_auth->is_supported());
    assert(signature->is_supported());

    std::cout << "Key Exchange: " << key_exchange->get_algorithm_name() << std::endl;
    std::cout << "Key Derivation: " << key_derivation->get_algorithm_name() << std::endl;
    std::cout << "Hash: " << hash->get_algorithm_name() << std::endl;
    std::cout << "Data Protection: " << data_protection->get_algorithm_name() << std::endl;
    std::cout << "Message Auth: " << message_auth->get_algorithm_name() << std::endl;
    std::cout << "Signature: " << signature->get_algorithm_name() << std::endl;

    // 5. 환경 변수 적용 테스트
    experiment::crypto::crypto_factory::get_instance().apply_to_environment("127.0.0.1", 8080);

    // 6. 다른 스위트로 변경 테스트
    bool switched = experiment::crypto::crypto_factory::get_instance().apply_crypto_suite("alt_chacha20");
    assert(switched);

    auto new_suite = experiment::crypto::crypto_factory::get_instance().get_active_suite();
    std::cout << "Switched to: " << new_suite->get_config().name << std::endl;
    std::cout << "New data protection: " << new_suite->get_data_protection()->get_algorithm_name() << std::endl;

    // 7. 플러그인 테스트
    std::cout << "\nTesting plugin system..." << std::endl;
    auto& plugin_mgr = experiment::crypto::plugin_manager::get_instance();

    // 샘플 플러그인 로드 시도 (실제로는 파일이 없을 수 있음)
    std::string plugin_path = "./plugins/libcustom_crypto.so";
    if (plugin_mgr.load_plugin(plugin_path)) {
        std::cout << "Plugin loaded successfully" << std::endl;

        // 로드된 플러그인 목록 확인
        auto loaded_plugins = plugin_mgr.get_loaded_plugins();
        std::cout << "Loaded plugins: " << loaded_plugins.size() << std::endl;
        for (const auto& plugin_name : loaded_plugins) {
            std::cout << "  - " << plugin_name << std::endl;
        }

        // SHA3 해시 테스트
        auto sha3_hash = plugin_mgr.create_hash("SHA3-256");
        if (sha3_hash) {
            std::cout << "SHA3-256 hash created from plugin: " << sha3_hash->get_algorithm_name() << std::endl;
        } else {
            std::cout << "SHA3-256 not available from plugins, using built-in" << std::endl;
        }

        // 플러그인 언로드
        for (const auto& plugin_name : loaded_plugins) {
            plugin_mgr.unload_plugin(plugin_name);
        }
    } else {
        std::cout << "Plugin not available (expected if not built): " << plugin_path << std::endl;
    }

    // 8. 플러그인을 통한 알고리즘 생성 테스트
    std::cout << "Testing algorithm creation through plugins..." << std::endl;

    // SHA3 스위트가 있다면 테스트
    experiment::config::crypto_suite_config sha3_suite;
    sha3_suite.name = "sha3_test_suite";
    sha3_suite.hash = "SHA3-256";
    sha3_suite.key_exchange = "ECDHE-P256";
    sha3_suite.key_derivation = "HKDF-SHA256";
    sha3_suite.data_protection = "AES256-GCM";
    sha3_suite.message_auth = "HMAC-SHA256";
    sha3_suite.signature = "ECDSA-P256";

    experiment::crypto::crypto_suite sha3_crypto_suite(sha3_suite);
    std::cout << "SHA3 suite hash algorithm: " << sha3_crypto_suite.get_hash()->get_algorithm_name() << std::endl;

    std::cout << "All tests passed!" << std::endl;
    return 0;
}
