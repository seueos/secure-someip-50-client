#include "../../include/crypto/crypto_factory.hpp"
#include "../../include/config/crypto_config.hpp"
#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <dlfcn.h>
#include <unordered_map>

namespace experiment {
namespace crypto {

// 기본 구현체들 (현재는 로깅만 하는 stub)
class basic_key_exchange : public key_exchange_interface {
public:
    basic_key_exchange(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; } // 기본적으로 모두 지원한다고 가정
private:
    std::string algorithm_;
};

class basic_key_derivation : public key_derivation_interface {
public:
    basic_key_derivation(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; }
private:
    std::string algorithm_;
};

class basic_hash : public hash_interface {
public:
    basic_hash(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; }
private:
    std::string algorithm_;
};

class basic_data_protection : public data_protection_interface {
public:
    basic_data_protection(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; }
private:
    std::string algorithm_;
};

class basic_message_auth : public message_auth_interface {
public:
    basic_message_auth(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; }
private:
    std::string algorithm_;
};

class basic_signature : public signature_interface {
public:
    basic_signature(const std::string& algorithm) : algorithm_(algorithm) {}
    std::string get_algorithm_name() const override { return algorithm_; }
    bool is_supported() const override { return true; }
private:
    std::string algorithm_;
};

// crypto_suite 구현
crypto_suite::crypto_suite(const config::crypto_suite_config& config)
    : config_(config) {
    // 현재는 기본 구현체들만 생성 (실제 OpenSSL 연동은 추후 확장)
    key_exchange_ = std::make_shared<basic_key_exchange>(config.key_exchange);
    key_derivation_ = std::make_shared<basic_key_derivation>(config.key_derivation);
    hash_ = std::make_shared<basic_hash>(config.hash);
    data_protection_ = std::make_shared<basic_data_protection>(config.data_protection);
    message_auth_ = std::make_shared<basic_message_auth>(config.message_auth);
    signature_ = std::make_shared<basic_signature>(config.signature);
}

std::shared_ptr<key_exchange_interface> crypto_suite::get_key_exchange() const {
    return key_exchange_;
}

std::shared_ptr<key_derivation_interface> crypto_suite::get_key_derivation() const {
    return key_derivation_;
}

std::shared_ptr<hash_interface> crypto_suite::get_hash() const {
    return hash_;
}

std::shared_ptr<data_protection_interface> crypto_suite::get_data_protection() const {
    return data_protection_;
}

std::shared_ptr<message_auth_interface> crypto_suite::get_message_auth() const {
    return message_auth_;
}

std::shared_ptr<signature_interface> crypto_suite::get_signature() const {
    return signature_;
}

const config::crypto_suite_config& crypto_suite::get_config() const {
    return config_;
}

// crypto_factory 구현
// 플러그인 생성 함수 타입 정의
using create_plugin_func = crypto_plugin* (*)();

// 플러그인 매니저 구현
plugin_manager& plugin_manager::get_instance() {
    static plugin_manager instance;
    return instance;
}

bool plugin_manager::load_plugin(const std::string& plugin_path) {
    // 이미 로드된 플러그인인지 확인
    if (plugin_handles_.find(plugin_path) != plugin_handles_.end()) {
        std::cout << "Plugin already loaded: " << plugin_path << std::endl;
        return true;
    }

    // 동적 라이브러리 로드
    void* handle = dlopen(plugin_path.c_str(), RTLD_LAZY);
    if (!handle) {
        std::cerr << "Failed to load plugin " << plugin_path << ": " << dlerror() << std::endl;
        return false;
    }

    // create_plugin 함수 찾기
    dlerror(); // 에러 초기화
    create_plugin_func create_plugin = (create_plugin_func)dlsym(handle, "create_plugin");
    const char* dlsym_error = dlerror();
    if (dlsym_error) {
        std::cerr << "Failed to find create_plugin function in " << plugin_path << ": " << dlsym_error << std::endl;
        dlclose(handle);
        return false;
    }

    // 플러그인 인스턴스 생성
    crypto_plugin* plugin_instance = create_plugin();
    if (!plugin_instance) {
        std::cerr << "Failed to create plugin instance from " << plugin_path << std::endl;
        dlclose(handle);
        return false;
    }

    // 플러그인 초기화
    if (!plugin_instance->initialize()) {
        std::cerr << "Failed to initialize plugin: " << plugin_instance->get_plugin_name() << std::endl;
        delete plugin_instance;
        dlclose(handle);
        return false;
    }

    // 플러그인 등록
    std::string plugin_name = plugin_instance->get_plugin_name();
    loaded_plugins_[plugin_name] = std::shared_ptr<crypto_plugin>(plugin_instance);
    plugin_handles_[plugin_name] = handle;

    std::cout << "Successfully loaded plugin: " << plugin_name
              << " (version: " << plugin_instance->get_plugin_version() << ")" << std::endl;
    return true;
}

bool plugin_manager::unload_plugin(const std::string& plugin_name) {
    auto plugin_it = loaded_plugins_.find(plugin_name);
    auto handle_it = plugin_handles_.find(plugin_name);

    if (plugin_it == loaded_plugins_.end() || handle_it == plugin_handles_.end()) {
        std::cerr << "Plugin not found: " << plugin_name << std::endl;
        return false;
    }

    // 플러그인 종료
    plugin_it->second->shutdown();

    // 핸들 언로드
    if (dlclose(handle_it->second) != 0) {
        std::cerr << "Warning: Failed to close plugin handle: " << plugin_name << std::endl;
    }

    // 맵에서 제거
    loaded_plugins_.erase(plugin_it);
    plugin_handles_.erase(handle_it);

    std::cout << "Unloaded plugin: " << plugin_name << std::endl;
    return true;
}

void plugin_manager::unload_all_plugins() {
    for (const auto& plugin : loaded_plugins_) {
        plugin.second->shutdown();
    }

    for (const auto& handle : plugin_handles_) {
        dlclose(handle.second);
    }

    loaded_plugins_.clear();
    plugin_handles_.clear();
}

std::shared_ptr<crypto_plugin> plugin_manager::get_plugin(const std::string& plugin_name) const {
    auto it = loaded_plugins_.find(plugin_name);
    return (it != loaded_plugins_.end()) ? it->second : nullptr;
}

std::vector<std::string> plugin_manager::get_loaded_plugins() const {
    std::vector<std::string> plugin_names;
    for (const auto& plugin : loaded_plugins_) {
        plugin_names.push_back(plugin.first);
    }
    return plugin_names;
}

// 알고리즘 생성 헬퍼 함수들
template<typename T>
std::shared_ptr<T> create_algorithm_from_plugins(const std::string& algorithm,
                                               const std::unordered_map<std::string, std::shared_ptr<crypto_plugin>>& plugins,
                                               std::shared_ptr<T> (*create_func)(crypto_plugin*, const std::string&)) {
    for (const auto& plugin_pair : plugins) {
        try {
            auto result = create_func(plugin_pair.second.get(), algorithm);
            if (result) {
                return result;
            }
        } catch (const std::exception& e) {
            // 플러그인에서 해당 알고리즘을 지원하지 않는 경우 계속 시도
            continue;
        }
    }
    return nullptr; // 어떤 플러그인도 해당 알고리즘을 지원하지 않음
}

std::shared_ptr<key_exchange_interface> plugin_manager::create_key_exchange(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_key_exchange(alg);
        });
}

std::shared_ptr<key_derivation_interface> plugin_manager::create_key_derivation(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_key_derivation(alg);
        });
}

std::shared_ptr<hash_interface> plugin_manager::create_hash(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_hash(alg);
        });
}

std::shared_ptr<data_protection_interface> plugin_manager::create_data_protection(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_data_protection(alg);
        });
}

std::shared_ptr<message_auth_interface> plugin_manager::create_message_auth(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_message_auth(alg);
        });
}

std::shared_ptr<signature_interface> plugin_manager::create_signature(const std::string& algorithm) {
    return create_algorithm_from_plugins(algorithm, loaded_plugins_,
        [](crypto_plugin* plugin, const std::string& alg) {
            return plugin->create_signature(alg);
        });
}

// crypto_suite의 알고리즘 생성을 플러그인 우선으로 수정
crypto_suite::crypto_suite(const config::crypto_suite_config& config)
    : config_(config) {
    auto& plugin_mgr = plugin_manager::get_instance();

    // 각 카테고리별로 플러그인에서 생성 시도, 실패시 기본 구현 사용
    key_exchange_ = plugin_mgr.create_key_exchange(config.key_exchange);
    if (!key_exchange_) {
        key_exchange_ = std::make_shared<basic_key_exchange>(config.key_exchange);
    }

    key_derivation_ = plugin_mgr.create_key_derivation(config.key_derivation);
    if (!key_derivation_) {
        key_derivation_ = std::make_shared<basic_key_derivation>(config.key_derivation);
    }

    hash_ = plugin_mgr.create_hash(config.hash);
    if (!hash_) {
        hash_ = std::make_shared<basic_hash>(config.hash);
    }

    data_protection_ = plugin_mgr.create_data_protection(config.data_protection);
    if (!data_protection_) {
        data_protection_ = std::make_shared<basic_data_protection>(config.data_protection);
    }

    message_auth_ = plugin_mgr.create_message_auth(config.message_auth);
    if (!message_auth_) {
        message_auth_ = std::make_shared<basic_message_auth>(config.message_auth);
    }

    signature_ = plugin_mgr.create_signature(config.signature);
    if (!signature_) {
        signature_ = std::make_shared<basic_signature>(config.signature);
    }
}

// crypto_factory 구현
crypto_factory& crypto_factory::get_instance() {
    static crypto_factory instance;
    return instance;
}

bool crypto_factory::load_config(const std::string& config_path) {
    try {
        current_config_ = config::crypto_config_loader::load_from_file(config_path);
        std::cout << "Loaded crypto config from: " << config_path << std::endl;
        std::cout << "Active suite: " << current_config_.active_suite << std::endl;
        std::cout << "Available suites: " << current_config_.suites.size() << std::endl;

        // 플러그인들 로드
        load_plugins_from_config();

        // 활성 스위트 적용
        if (!current_config_.active_suite.empty()) {
            return apply_crypto_suite(current_config_.active_suite);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load crypto config: " << e.what() << std::endl;
        return false;
    }
}

bool crypto_factory::load_plugins_from_config() {
    bool all_success = true;

    for (const auto& plugin : current_config_.plugins) {
        if (!plugin.enabled) {
            std::cout << "Plugin " << plugin.name << " is disabled, skipping" << std::endl;
            continue;
        }

        std::cout << "Loading plugin: " << plugin.name << " from " << plugin.path << std::endl;
        if (!plugin_mgr_.load_plugin(plugin.path)) {
            std::cerr << "Failed to load plugin: " << plugin.name << std::endl;
            all_success = false;
        }
    }

    if (current_config_.plugins.empty()) {
        std::cout << "No plugins specified in config - using built-in implementations" << std::endl;
    }

    return all_success;
}

bool crypto_factory::register_plugin(const std::string& plugin_path) {
    return plugin_mgr_.load_plugin(plugin_path);
}

bool crypto_factory::apply_crypto_suite(const std::string& suite_name) {
    auto it = std::find_if(current_config_.suites.begin(), current_config_.suites.end(),
                          [&suite_name](const config::crypto_suite_config& suite) {
                              return suite.name == suite_name;
                          });

    if (it == current_config_.suites.end()) {
        std::cerr << "Crypto suite not found: " << suite_name << std::endl;
        return false;
    }

    active_suite_ = std::make_shared<crypto_suite>(*it);
    std::cout << "Applied crypto suite: " << suite_name << std::endl;
    return true;
}

std::shared_ptr<crypto_suite> crypto_factory::get_active_suite() const {
    return active_suite_;
}

void crypto_factory::apply_to_environment(const std::string& address, uint16_t port) {
    if (!active_suite_ || !current_config_.enable_experiment) {
        return;
    }

    const auto& config = active_suite_->get_config();

    // 기존 vSomeIP TLS 설정들을 기반으로 새로운 카테고리들을 환경 변수로 설정
    // 참고: 실제 OpenSSL 적용을 위해서는 더 복잡한 로직이 필요함

    // 키 교환 설정 (기존 groups 설정과 매핑)
    if (!config.key_exchange.empty()) {
        std::string groups = map_key_exchange_to_groups(config.key_exchange);
        if (!groups.empty()) {
            setenv("VSOMEIP_TLS_GROUPS", groups.c_str(), 1);
        }
    }

    // 서명 알고리즘 설정 (기존 sigalgs 설정과 매핑)
    if (!config.signature.empty()) {
        std::string sigalgs = map_signature_to_sigalgs(config.signature);
        if (!sigalgs.empty()) {
            setenv("VSOMEIP_TLS_SIGALGS", sigalgs.c_str(), 1);
        }
    }

    // 새로운 실험용 설정들
    if (!config.key_derivation.empty()) {
        setenv("VSOMEIP_TLS_KEY_DERIVATION", config.key_derivation.c_str(), 1);
    }
    if (!config.hash.empty()) {
        setenv("VSOMEIP_TLS_HASH", config.hash.c_str(), 1);
    }
    if (!config.data_protection.empty()) {
        // 기존 cipher suites와 매핑
        std::string ciphersuites = map_data_protection_to_ciphersuites(config.data_protection);
        if (!ciphersuites.empty()) {
            setenv("VSOMEIP_TLS_CIPHERSUITES13", ciphersuites.c_str(), 1);
        }
    }
    if (!config.message_auth.empty()) {
        setenv("VSOMEIP_TLS_MESSAGE_AUTH", config.message_auth.c_str(), 1);
    }

    std::cout << "Applied crypto suite '" << config.name << "' to environment for "
              << address << ":" << port << std::endl;
}

// 헬퍼 함수들 (실제 매핑 로직은 향후 구현)
std::string crypto_factory::map_key_exchange_to_groups(const std::string& key_exchange) {
    if (key_exchange.find("ECDHE-P256") != std::string::npos) return "P-256";
    if (key_exchange.find("ECDHE-P384") != std::string::npos) return "P-384";
    if (key_exchange.find("X25519") != std::string::npos) return "X25519";
    return "";
}

std::string crypto_factory::map_signature_to_sigalgs(const std::string& signature) {
    if (signature.find("ECDSA-P256") != std::string::npos) return "ecdsa_secp256r1_sha256";
    if (signature.find("ECDSA-P384") != std::string::npos) return "ecdsa_secp384r1_sha384";
    if (signature.find("Ed25519") != std::string::npos) return "ed25519";
    return "";
}

std::string crypto_factory::map_data_protection_to_ciphersuites(const std::string& data_protection) {
    if (data_protection.find("AES256-GCM") != std::string::npos) return "TLS_AES_256_GCM_SHA384";
    if (data_protection.find("AES128-GCM") != std::string::npos) return "TLS_AES_128_GCM_SHA256";
    if (data_protection.find("ChaCha20-Poly1305") != std::string::npos) return "TLS_CHACHA20_POLY1305_SHA256";
    return "";
}

} // namespace crypto
} // namespace experiment
