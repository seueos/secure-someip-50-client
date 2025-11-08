#include "../include/config/crypto_config.hpp"
#include "../include/crypto/crypto_factory.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace experiment;

// 알고리즘 옵션들 정의
const std::vector<std::string> KEY_EXCHANGE_OPTIONS = {
    "ECDHE-P256", "ECDHE-P384", "X25519"
};

const std::vector<std::string> KEY_DERIVATION_OPTIONS = {
    "HKDF-SHA256", "HKDF-SHA384"
};

const std::vector<std::string> HASH_OPTIONS = {
    "SHA256", "SHA384", "SHA3-256"
};

const std::vector<std::string> DATA_PROTECTION_OPTIONS = {
    "AES256-GCM", "AES128-GCM", "ChaCha20-Poly1305"
};

const std::vector<std::string> MESSAGE_AUTH_OPTIONS = {
    "HMAC-SHA256", "HMAC-SHA384", "Poly1305"
};

const std::vector<std::string> SIGNATURE_OPTIONS = {
    "ECDSA-P256", "ECDSA-P384", "Ed25519"
};

// 조합 생성 함수
std::vector<config::crypto_suite_config> generate_all_combinations() {
    std::vector<config::crypto_suite_config> combinations;

    for (const auto& ke : KEY_EXCHANGE_OPTIONS) {
        for (const auto& kd : KEY_DERIVATION_OPTIONS) {
            for (const auto& h : HASH_OPTIONS) {
                for (const auto& dp : DATA_PROTECTION_OPTIONS) {
                    for (const auto& ma : MESSAGE_AUTH_OPTIONS) {
                        for (const auto& sig : SIGNATURE_OPTIONS) {
                            config::crypto_suite_config suite;
                            suite.name = ke + "_" + kd + "_" + h + "_" + dp + "_" + ma + "_" + sig;
                            suite.description = "Auto-generated combination";
                            suite.key_exchange = ke;
                            suite.key_derivation = kd;
                            suite.hash = h;
                            suite.data_protection = dp;
                            suite.message_auth = ma;
                            suite.signature = sig;

                            combinations.push_back(suite);
                        }
                    }
                }
            }
        }
    }

    return combinations;
}

// 호환성 검증 함수
bool validate_compatibility(const config::crypto_suite_config& suite) {
    // 기본적인 호환성 검증

    // ECDSA 서명은 ECDHE 키 교환과 호환
    if (suite.signature.find("ECDSA") != std::string::npos) {
        if (suite.key_exchange.find("ECDHE") == std::string::npos) {
            return false;
        }
    }

    // Ed25519는 X25519 키 교환과 호환
    if (suite.signature == "Ed25519") {
        if (suite.key_exchange != "X25519") {
            return false;
        }
    }

    // ChaCha20-Poly1305는 AEAD이므로 별도 메시지 인증 불필요하지만 허용
    if (suite.data_protection == "ChaCha20-Poly1305") {
        // Poly1305 메시지 인증과 함께 사용하는 것은 중복될 수 있지만 허용
    }

    return true;
}

// 성능 등급 계산 함수 (임의의 메트릭)
int calculate_performance_score(const config::crypto_suite_config& suite) {
    int score = 0;

    // 키 교환 성능
    if (suite.key_exchange == "X25519") score += 10;      // 가장 빠름
    else if (suite.key_exchange == "ECDHE-P256") score += 8;
    else if (suite.key_exchange == "ECDHE-P384") score += 6;

    // 데이터 보호 성능
    if (suite.data_protection == "ChaCha20-Poly1305") score += 10;  // 가장 빠름
    else if (suite.data_protection == "AES128-GCM") score += 8;
    else if (suite.data_protection == "AES256-GCM") score += 6;

    // 해시 성능
    if (suite.hash == "SHA256") score += 8;
    else if (suite.hash == "SHA3-256") score += 6;
    else if (suite.hash == "SHA384") score += 4;

    return score;
}

// 보안 강도 계산 함수
int calculate_security_score(const config::crypto_suite_config& suite) {
    int score = 0;

    // 키 교환 보안
    if (suite.key_exchange == "ECDHE-P384") score += 10;  // 가장 강력
    else if (suite.key_exchange == "X25519") score += 9;
    else if (suite.key_exchange == "ECDHE-P256") score += 8;

    // 데이터 보호 보안
    if (suite.data_protection == "AES256-GCM") score += 10;  // 가장 강력
    else if (suite.data_protection == "AES128-GCM") score += 8;
    else if (suite.data_protection == "ChaCha20-Poly1305") score += 9;

    // 서명 보안
    if (suite.signature == "ECDSA-P384") score += 10;
    else if (suite.signature == "Ed25519") score += 9;
    else if (suite.signature == "ECDSA-P256") score += 8;

    return score;
}

int main() {
    std::cout << "vSomeIP TLS Crypto Combination Tester" << std::endl;
    std::cout << "====================================" << std::endl;

    // 모든 가능한 조합 생성
    auto all_combinations = generate_all_combinations();
    std::cout << "Generated " << all_combinations.size() << " possible combinations" << std::endl;

    // 호환성 검증 및 필터링
    std::vector<config::crypto_suite_config> valid_combinations;
    for (const auto& combo : all_combinations) {
        if (validate_compatibility(combo)) {
            valid_combinations.push_back(combo);
        }
    }

    std::cout << "Valid combinations after compatibility check: " << valid_combinations.size() << std::endl;

    // 상위 10개 조합 선정 (성능 + 보안 점수 기준)
    std::vector<std::tuple<int, int, config::crypto_suite_config>> scored_combinations;

    for (const auto& combo : valid_combinations) {
        int perf_score = calculate_performance_score(combo);
        int sec_score = calculate_security_score(combo);
        int total_score = perf_score + sec_score;
        scored_combinations.emplace_back(total_score, sec_score, combo);
    }

    // 점수 기준 내림차순 정렬
    std::sort(scored_combinations.rbegin(), scored_combinations.rend());

    // 상위 10개 출력
    std::cout << "\nTop 10 Recommended Combinations:" << std::endl;
    std::cout << "=================================" << std::endl;

    config::crypto_config recommended_config;
    recommended_config.active_suite = "recommended_high_perf";
    recommended_config.enable_experiment = true;

    for (size_t i = 0; i < std::min(size_t(10), scored_combinations.size()); ++i) {
        const auto& [total_score, sec_score, suite] = scored_combinations[i];

        std::cout << (i+1) << ". " << suite.name << std::endl;
        std::cout << "   Total Score: " << total_score << " (Security: " << sec_score << ")" << std::endl;
        std::cout << "   KE: " << suite.key_exchange
                  << ", KD: " << suite.key_derivation
                  << ", Hash: " << suite.hash << std::endl;
        std::cout << "   Data: " << suite.data_protection
                  << ", Auth: " << suite.message_auth
                  << ", Sig: " << suite.signature << std::endl;
        std::cout << std::endl;

        if (i < 5) {  // 상위 5개만 설정에 추가
            suite.description = "Recommended combination #" + std::to_string(i+1) +
                               " (Score: " + std::to_string(total_score) + ")";
            recommended_config.suites.push_back(suite);
        }
    }

    // 추천 설정 저장
    config::crypto_config_loader::save_to_file("../config/recommended_suites.json", recommended_config);
    std::cout << "Recommended configurations saved to ../config/recommended_suites.json" << std::endl;

    // 팩토리로 로드 및 테스트
    std::cout << "\nTesting with crypto factory..." << std::endl;
    auto& factory = crypto::crypto_factory::get_instance();

    if (factory.load_config("../config/recommended_suites.json")) {
        std::cout << "Successfully loaded recommended config" << std::endl;

        // 첫 번째 추천 스위트로 테스트
        if (!recommended_config.suites.empty()) {
            factory.apply_crypto_suite(recommended_config.suites[0].name);
            auto active_suite = factory.get_active_suite();

            if (active_suite) {
                std::cout << "Active suite: " << active_suite->get_config().name << std::endl;
                std::cout << "All algorithms supported: "
                          << (active_suite->get_key_exchange()->is_supported() &&
                              active_suite->get_key_derivation()->is_supported() &&
                              active_suite->get_hash()->is_supported() &&
                              active_suite->get_data_protection()->is_supported() &&
                              active_suite->get_message_auth()->is_supported() &&
                              active_suite->get_signature()->is_supported()
                              ? "YES" : "NO") << std::endl;
            }
        }
    }

    std::cout << "\nCombination testing completed!" << std::endl;
    return 0;
}
