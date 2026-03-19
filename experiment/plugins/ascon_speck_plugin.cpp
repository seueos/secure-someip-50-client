#include "../include/crypto/crypto_factory.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <stdexcept>

namespace experiment {
namespace crypto {

static inline void ensure(bool cond, const char* msg) {
    if (!cond) throw std::runtime_error(msg);
}

// HKDF-SHA256
class hkdf_sha256 final : public key_derivation_interface {
public:
    std::string get_algorithm_name() const override { return "HKDF-SHA256"; }
    bool is_supported() const override { return true; }
    std::vector<std::uint8_t> derive(const std::vector<std::uint8_t>& ikm,
                                     const std::vector<std::uint8_t>& salt,
                                     const std::vector<std::uint8_t>& info,
                                     std::size_t out_len) override {
        std::vector<std::uint8_t> out(out_len, 0);
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        ensure(pctx != nullptr, "EVP_PKEY_CTX_new_id failed");
        ensure(EVP_PKEY_derive_init(pctx) == 1, "EVP_PKEY_derive_init failed");
        ensure(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1, "set_hkdf_md failed");
        ensure(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) == 1, "set1_hkdf_salt failed");
        ensure(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size())) == 1, "set1_hkdf_key failed");
        if (!info.empty()) {
            ensure(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) == 1, "add1_hkdf_info failed");
        }
        size_t len = out.size();
        ensure(EVP_PKEY_derive(pctx, out.data(), &len) == 1, "EVP_PKEY_derive failed");
        out.resize(len);
        EVP_PKEY_CTX_free(pctx);
        return out;
    }
};

// ASCON-HASH/XOF placeholder -> SHA3-256
class ascon_hash_placeholder final : public hash_interface {
public:
    explicit ascon_hash_placeholder(std::string alg) : alg_(std::move(alg)) {}
    std::string get_algorithm_name() const override { return alg_; }
    bool is_supported() const override { return true; }
    std::vector<std::uint8_t> compute(const std::vector<std::uint8_t>& data) override {
        const EVP_MD* md = EVP_sha3_256();
        std::vector<std::uint8_t> out(EVP_MD_size(md));
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        ensure(ctx != nullptr, "EVP_MD_CTX_new failed");
        ensure(EVP_DigestInit_ex(ctx, md, nullptr) == 1, "DigestInit failed");
        ensure(EVP_DigestUpdate(ctx, data.data(), data.size()) == 1, "DigestUpdate failed");
        unsigned int len = 0;
        ensure(EVP_DigestFinal_ex(ctx, out.data(), &len) == 1, "DigestFinal failed");
        out.resize(len);
        EVP_MD_CTX_free(ctx);
        return out;
    }
private:
    std::string alg_;
};

// ASCON-128 AEAD placeholder -> AES-128-GCM
class ascon128_aead_placeholder final : public data_protection_interface {
public:
    std::string get_algorithm_name() const override { return "ASCON-128 AEAD"; }
    bool is_supported() const override { return true; }
    std::vector<std::uint8_t> seal(const std::vector<std::uint8_t>& key,
                                   const std::vector<std::uint8_t>& nonce,
                                   const std::vector<std::uint8_t>& aad,
                                   const std::vector<std::uint8_t>& plaintext) override {
        const EVP_CIPHER* cipher = EVP_aes_128_gcm();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
        ensure(key.size() == 16, "AES-128-GCM requires 16-byte key (placeholder)");
        ensure(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1, "EncryptInit_ex failed");
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1, "SET_IVLEN failed");
        ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "EncryptInit key/iv failed");
        int len = 0;
        if (!aad.empty()) {
            ensure(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1, "AAD EncryptUpdate failed");
        }
        std::vector<std::uint8_t> out(plaintext.size() + 16);
        int ct_len = 0;
        ensure(EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1, "EncryptUpdate failed");
        ct_len = len;
        ensure(EVP_EncryptFinal_ex(ctx, out.data() + ct_len, &len) == 1, "EncryptFinal failed");
        ct_len += len;
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + ct_len) == 1, "GET_TAG failed");
        ct_len += 16;
        out.resize(ct_len);
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    std::vector<std::uint8_t> open(const std::vector<std::uint8_t>& key,
                                   const std::vector<std::uint8_t>& nonce,
                                   const std::vector<std::uint8_t>& aad,
                                   const std::vector<std::uint8_t>& ciphertext_and_tag) override {
        const EVP_CIPHER* cipher = EVP_aes_128_gcm();
        ensure(ciphertext_and_tag.size() >= 16, "ciphertext too short");
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
        ensure(key.size() == 16, "AES-128-GCM requires 16-byte key (placeholder)");
        ensure(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1, "DecryptInit failed");
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1, "SET_IVLEN failed");
        ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "DecryptInit key/iv failed");
        int len = 0;
        if (!aad.empty()) {
            ensure(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1, "AAD DecryptUpdate failed");
        }
        const size_t ct_len = ciphertext_and_tag.size() - 16;
        std::vector<std::uint8_t> out(ct_len);
        int pt_len = 0;
        ensure(EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext_and_tag.data(), static_cast<int>(ct_len)) == 1, "DecryptUpdate failed");
        pt_len = len;
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(ciphertext_and_tag.data() + ct_len)) == 1,
               "SET_TAG failed");
        int ret = EVP_DecryptFinal_ex(ctx, out.data() + pt_len, &len);
        EVP_CIPHER_CTX_free(ctx);
        if (ret != 1) return {};
        pt_len += len;
        out.resize(pt_len);
        return out;
    }
};

// SPECK placeholder -> ChaCha20-Poly1305 (for differentiation)
class speck_aead_placeholder final : public data_protection_interface {
public:
    std::string get_algorithm_name() const override { return "SPECK"; }
    bool is_supported() const override { return true; }
    std::vector<std::uint8_t> seal(const std::vector<std::uint8_t>& key,
                                   const std::vector<std::uint8_t>& nonce,
                                   const std::vector<std::uint8_t>& aad,
                                   const std::vector<std::uint8_t>& plaintext) override {
        const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
        ensure(key.size() == 32, "ChaCha20-Poly1305 requires 32-byte key (placeholder)");
        ensure(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1, "EncryptInit_ex failed");
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1, "SET_IVLEN failed");
        ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "EncryptInit key/iv failed");
        int len = 0;
        if (!aad.empty()) {
            ensure(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1, "AAD EncryptUpdate failed");
        }
        std::vector<std::uint8_t> out(plaintext.size() + 16);
        int ct_len = 0;
        ensure(EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1, "EncryptUpdate failed");
        ct_len = len;
        ensure(EVP_EncryptFinal_ex(ctx, out.data() + ct_len, &len) == 1, "EncryptFinal failed");
        ct_len += len;
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + ct_len) == 1, "GET_TAG failed");
        ct_len += 16;
        out.resize(ct_len);
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
    std::vector<std::uint8_t> open(const std::vector<std::uint8_t>& key,
                                   const std::vector<std::uint8_t>& nonce,
                                   const std::vector<std::uint8_t>& aad,
                                   const std::vector<std::uint8_t>& ciphertext_and_tag) override {
        const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
        ensure(ciphertext_and_tag.size() >= 16, "ciphertext too short");
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");
        ensure(key.size() == 32, "ChaCha20-Poly1305 requires 32-byte key (placeholder)");
        ensure(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1, "DecryptInit failed");
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1, "SET_IVLEN failed");
        ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "DecryptInit key/iv failed");
        int len = 0;
        if (!aad.empty()) {
            ensure(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1, "AAD DecryptUpdate failed");
        }
        const size_t ct_len = ciphertext_and_tag.size() - 16;
        std::vector<std::uint8_t> out(ct_len);
        int pt_len = 0;
        ensure(EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext_and_tag.data(), static_cast<int>(ct_len)) == 1, "DecryptUpdate failed");
        pt_len = len;
        ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(ciphertext_and_tag.data() + ct_len)) == 1,
               "SET_TAG failed");
        int ret = EVP_DecryptFinal_ex(ctx, out.data() + pt_len, &len);
        EVP_CIPHER_CTX_free(ctx);
        if (ret != 1) return {};
        pt_len += len;
        out.resize(pt_len);
        return out;
    }
};

// ASCON-MAC placeholder -> HMAC-SHA256
class ascon_mac_placeholder final : public message_auth_interface {
public:
    std::string get_algorithm_name() const override { return "ASCON-MAC"; }
    bool is_supported() const override { return true; }
    std::vector<std::uint8_t> mac(const std::vector<std::uint8_t>& key,
                                  const std::vector<std::uint8_t>& nonce,
                                  const std::vector<std::uint8_t>& data) override {
        (void)nonce;
        unsigned int len = 0;
        std::vector<std::uint8_t> out(EVP_MAX_MD_SIZE);
        unsigned char* res = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                                  data.data(), data.size(), out.data(), &len);
        if (!res) return {};
        out.resize(len);
        return out;
    }
    bool verify(const std::vector<std::uint8_t>& key,
                const std::vector<std::uint8_t>& nonce,
                const std::vector<std::uint8_t>& data,
                const std::vector<std::uint8_t>& tag) override {
        auto t = mac(key, nonce, data);
        if (t.size() != tag.size()) return false;
        unsigned int diff = 0;
        for (size_t i = 0; i < t.size(); ++i) diff |= (t[i] ^ tag[i]);
        return diff == 0;
    }
};

class ascon_speck_plugin final : public crypto_plugin {
public:
    std::string get_plugin_name() const override { return "ascon_speck_plugin"; }
    std::string get_plugin_version() const override { return "0.1.0"; }
    bool initialize() override {
        std::cout << "ascon_speck_plugin initialized (placeholders using OpenSSL)" << std::endl;
        return true;
    }
    void shutdown() override {
        std::cout << "ascon_speck_plugin shutdown" << std::endl;
    }
    std::shared_ptr<key_exchange_interface> create_key_exchange(const std::string& algorithm) override {
        (void)algorithm; return nullptr;
    }
    std::shared_ptr<key_derivation_interface> create_key_derivation(const std::string& algorithm) override {
        if (algorithm == "HKDF-SHA256") return std::make_shared<hkdf_sha256>();
        return nullptr;
    }
    std::shared_ptr<hash_interface> create_hash(const std::string& algorithm) override {
        if (algorithm == "ASCON-HASH" || algorithm == "ASCON-XOF") return std::make_shared<ascon_hash_placeholder>(algorithm);
        return nullptr;
    }
    std::shared_ptr<data_protection_interface> create_data_protection(const std::string& algorithm) override {
        if (algorithm == "ASCON-128 AEAD") return std::make_shared<ascon128_aead_placeholder>();
        if (algorithm == "SPECK") return std::make_shared<speck_aead_placeholder>();
        return nullptr;
    }
    std::shared_ptr<message_auth_interface> create_message_auth(const std::string& algorithm) override {
        if (algorithm == "ASCON-MAC") return std::make_shared<ascon_mac_placeholder>();
        return nullptr;
    }
    std::shared_ptr<signature_interface> create_signature(const std::string& algorithm) override {
        (void)algorithm; return nullptr;
    }
};

} // namespace crypto
} // namespace experiment

extern "C" experiment::crypto::crypto_plugin* create_plugin() {
    return new experiment::crypto::ascon_speck_plugin();
}


