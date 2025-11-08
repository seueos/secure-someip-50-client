#include "../../include/crypto/crypto_factory.hpp"
#include <iostream>
#include <openssl/evp.h>

namespace experiment {
namespace crypto {

// SHA3 해시 구현체
class sha3_hash : public hash_interface {
public:
    sha3_hash(const std::string& algorithm) : algorithm_(algorithm) {
        // SHA3-256, SHA3-384 등 지원
        if (algorithm == "SHA3-256") {
            md_ = EVP_sha3_256();
        } else if (algorithm == "SHA3-384") {
            md_ = EVP_sha3_384();
        } else if (algorithm == "SHA3-512") {
            md_ = EVP_sha3_512();
        } else {
            throw std::runtime_error("Unsupported SHA3 variant: " + algorithm);
        }
    }

    std::string get_algorithm_name() const override {
        return algorithm_;
    }

    bool is_supported() const override {
        return md_ != nullptr;
    }

    // 실제 해시 계산 (간단한 구현)
    std::vector<uint8_t> compute_hash(const std::vector<uint8_t>& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> result(EVP_MD_size(md_));

        EVP_DigestInit_ex(ctx, md_, nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, result.data(), nullptr);

        EVP_MD_CTX_free(ctx);
        return result;
    }

private:
    std::string algorithm_;
    const EVP_MD* md_ = nullptr;
};

// 커스텀 암호화 플러그인 구현
class custom_crypto_plugin : public crypto_plugin {
public:
    std::string get_plugin_name() const override {
        return "custom_crypto_plugin";
    }

    std::string get_plugin_version() const override {
        return "1.0.0";
    }

    bool initialize() override {
        std::cout << "Custom crypto plugin initialized" << std::endl;
        return true;
    }

    void shutdown() override {
        std::cout << "Custom crypto plugin shutdown" << std::endl;
    }

    // SHA3 해시만 지원하는 예제
    std::shared_ptr<key_exchange_interface> create_key_exchange(const std::string& algorithm) override {
        return nullptr; // 지원하지 않음
    }

    std::shared_ptr<key_derivation_interface> create_key_derivation(const std::string& algorithm) override {
        return nullptr; // 지원하지 않음
    }

    std::shared_ptr<hash_interface> create_hash(const std::string& algorithm) override {
        if (algorithm.find("SHA3") == 0) {
            return std::make_shared<sha3_hash>(algorithm);
        }
        return nullptr;
    }

    std::shared_ptr<data_protection_interface> create_data_protection(const std::string& algorithm) override {
        return nullptr; // 지원하지 않음
    }

    std::shared_ptr<message_auth_interface> create_message_auth(const std::string& algorithm) override {
        return nullptr; // 지원하지 않음
    }

    std::shared_ptr<signature_interface> create_signature(const std::string& algorithm) override {
        return nullptr; // 지원하지 않음
    }
};

} // namespace crypto
} // namespace experiment

// 플러그인 생성 함수 (외부에서 호출됨)
extern "C" experiment::crypto::crypto_plugin* create_plugin() {
    return new experiment::crypto::custom_crypto_plugin();
}
