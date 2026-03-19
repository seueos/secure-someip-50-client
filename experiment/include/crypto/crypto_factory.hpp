#ifndef EXPERIMENT_CRYPTO_FACTORY_HPP
#define EXPERIMENT_CRYPTO_FACTORY_HPP

#include "../config/crypto_config.hpp"
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

namespace experiment {
namespace crypto {

// 암호화 알고리즘 인터페이스들
class key_exchange_interface {
public:
    virtual ~key_exchange_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
};

class key_derivation_interface {
public:
    virtual ~key_derivation_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
    virtual std::vector<std::uint8_t> derive(const std::vector<std::uint8_t>& ikm,
                                             const std::vector<std::uint8_t>& salt,
                                             const std::vector<std::uint8_t>& info,
                                             std::size_t out_len) = 0;
};

class hash_interface {
public:
    virtual ~hash_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
    virtual std::vector<std::uint8_t> compute(const std::vector<std::uint8_t>& data) = 0;
};

class data_protection_interface {
public:
    virtual ~data_protection_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
    virtual std::vector<std::uint8_t> seal(const std::vector<std::uint8_t>& key,
                                           const std::vector<std::uint8_t>& nonce,
                                           const std::vector<std::uint8_t>& aad,
                                           const std::vector<std::uint8_t>& plaintext) = 0;
    virtual std::vector<std::uint8_t> open(const std::vector<std::uint8_t>& key,
                                           const std::vector<std::uint8_t>& nonce,
                                           const std::vector<std::uint8_t>& aad,
                                           const std::vector<std::uint8_t>& ciphertext_and_tag) = 0;
};

class message_auth_interface {
public:
    virtual ~message_auth_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
    virtual std::vector<std::uint8_t> mac(const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& nonce,
                                          const std::vector<std::uint8_t>& data) = 0;
    virtual bool verify(const std::vector<std::uint8_t>& key,
                        const std::vector<std::uint8_t>& nonce,
                        const std::vector<std::uint8_t>& data,
                        const std::vector<std::uint8_t>& tag) = 0;
};

class signature_interface {
public:
    virtual ~signature_interface() = default;
    virtual std::string get_algorithm_name() const = 0;
    virtual bool is_supported() const = 0;
};

// 암호화 스위트 클래스
class crypto_suite {
public:
    crypto_suite(const config::crypto_suite_config& config);

    // 6가지 카테고리별 인터페이스 getter
    std::shared_ptr<key_exchange_interface> get_key_exchange() const;
    std::shared_ptr<key_derivation_interface> get_key_derivation() const;
    std::shared_ptr<hash_interface> get_hash() const;
    std::shared_ptr<data_protection_interface> get_data_protection() const;
    std::shared_ptr<message_auth_interface> get_message_auth() const;
    std::shared_ptr<signature_interface> get_signature() const;

    const config::crypto_suite_config& get_config() const;

private:
    config::crypto_suite_config config_;
    // 실제 구현체들은 나중에 추가
    std::shared_ptr<key_exchange_interface> key_exchange_;
    std::shared_ptr<key_derivation_interface> key_derivation_;
    std::shared_ptr<hash_interface> hash_;
    std::shared_ptr<data_protection_interface> data_protection_;
    std::shared_ptr<message_auth_interface> message_auth_;
    std::shared_ptr<signature_interface> signature_;
};

// 플러그인 인터페이스
class crypto_plugin {
public:
    virtual ~crypto_plugin() = default;
    virtual std::string get_plugin_name() const = 0;
    virtual std::string get_plugin_version() const = 0;
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;

    // 알고리즘 생성 인터페이스들
    virtual std::shared_ptr<key_exchange_interface> create_key_exchange(const std::string& algorithm) = 0;
    virtual std::shared_ptr<key_derivation_interface> create_key_derivation(const std::string& algorithm) = 0;
    virtual std::shared_ptr<hash_interface> create_hash(const std::string& algorithm) = 0;
    virtual std::shared_ptr<data_protection_interface> create_data_protection(const std::string& algorithm) = 0;
    virtual std::shared_ptr<message_auth_interface> create_message_auth(const std::string& algorithm) = 0;
    virtual std::shared_ptr<signature_interface> create_signature(const std::string& algorithm) = 0;
};

// 플러그인 매니저
class plugin_manager {
public:
    static plugin_manager& get_instance();

    // 플러그인 로드/언로드
    bool load_plugin(const std::string& plugin_path);
    bool unload_plugin(const std::string& plugin_name);
    void unload_all_plugins();

    // 플러그인 조회
    std::shared_ptr<crypto_plugin> get_plugin(const std::string& plugin_name) const;
    std::vector<std::string> get_loaded_plugins() const;

    // 알고리즘 생성 (플러그인을 통한)
    std::shared_ptr<key_exchange_interface> create_key_exchange(const std::string& algorithm);
    std::shared_ptr<key_derivation_interface> create_key_derivation(const std::string& algorithm);
    std::shared_ptr<hash_interface> create_hash(const std::string& algorithm);
    std::shared_ptr<data_protection_interface> create_data_protection(const std::string& algorithm);
    std::shared_ptr<message_auth_interface> create_message_auth(const std::string& algorithm);
    std::shared_ptr<signature_interface> create_signature(const std::string& algorithm);

private:
    plugin_manager() = default;
    ~plugin_manager() { unload_all_plugins(); }

    std::unordered_map<std::string, std::shared_ptr<crypto_plugin>> loaded_plugins_;
    std::unordered_map<std::string, void*> plugin_handles_; // dlopen 핸들들
};

// 팩토리 클래스
class crypto_factory {
public:
    static crypto_factory& get_instance();

    // 설정 적용
    bool load_config(const std::string& config_path);
    bool apply_crypto_suite(const std::string& suite_name);

    // 플러그인 관리
    bool load_plugins_from_config();
    bool register_plugin(const std::string& plugin_path);

    // 현재 활성화된 스위트 가져오기
    std::shared_ptr<crypto_suite> get_active_suite() const;

    // vSomeIP 환경 변수 설정 (실제 적용)
    void apply_to_environment(const std::string& address, uint16_t port);

private:
    crypto_factory() = default;
    ~crypto_factory() = default;
    crypto_factory(const crypto_factory&) = delete;
    crypto_factory& operator=(const crypto_factory&) = delete;

    config::crypto_config current_config_;
    std::shared_ptr<crypto_suite> active_suite_;
    plugin_manager& plugin_mgr_ = plugin_manager::get_instance();
};

} // namespace crypto
} // namespace experiment

#endif // EXPERIMENT_CRYPTO_FACTORY_HPP
