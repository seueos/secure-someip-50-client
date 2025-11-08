# vSomeIP TLS Crypto Experiment Framework

이 모듈은 vSomeIP의 TLS 구현에서 6가지 보안 카테고리를 실험적으로 커스터마이징할 수 있는 프레임워크를 제공합니다.

## 6가지 보안 카테고리

1. **키 교환 (Key Exchange)**: ECDHE-P256, ECDHE-P384, X25519 등
2. **키 유도 (Key Derivation)**: HKDF-SHA256, HKDF-SHA384 등
3. **해시 (Hash)**: SHA256, SHA384, SHA3-256 등
4. **데이터 보호 (Data Protection)**: AES256-GCM, AES128-GCM, ChaCha20-Poly1305 등
5. **메시지 인증 (Message Authentication)**: HMAC-SHA256, Poly1305 등
6. **서명/검증 (Signature)**: ECDSA-P256, ECDSA-P384, Ed25519, RSA-PSS 등

## 빌드 방법

```bash
cd experiment
mkdir build && cd build
cmake ..
make
```

## 사용 방법

### 1. 설정 파일 준비

`config/crypto_suites.json` 파일을 참고하여 원하는 암호화 스위트를 정의합니다:

```json
{
    "active_suite": "my_custom_suite",
    "enable_experiment": true,
    "suites": [
        {
            "name": "my_custom_suite",
            "description": "나만의 암호화 스위트",
            "key_exchange": "ECDHE-P256",
            "key_derivation": "HKDF-SHA256",
            "hash": "SHA256",
            "data_protection": "AES256-GCM",
            "message_auth": "HMAC-SHA256",
            "signature": "ECDSA-P256"
        }
    ]
}
```

### 2. vSomeIP 설정에 통합

vSomeIP의 설정 파일에서 TLS 설정을 추가합니다:

```json
{
    "services": [
        {
            "service": "0x1111",
            "instance": "0x2222",
            "unicast_address": "127.0.0.1",
            "reliable": "0x3049",
            "tls": {
                "key-derivation": "HKDF-SHA256",
                "hash": "SHA256",
                "message-auth": "HMAC-SHA256"
            }
        }
    ]
}
```

### 3. 애플리케이션에서 사용

```cpp
#include "experiment/crypto/crypto_factory.hpp"

// 설정 로드
auto& factory = experiment::crypto::crypto_factory::get_instance();
factory.load_config("path/to/crypto_suites.json");

// 특정 endpoint에 적용
factory.apply_to_environment("127.0.0.1", 3049);
```

## 플러그인 시스템

experiment 프레임워크는 동적 플러그인을 통해 새로운 암호화 알고리즘을 쉽게 추가할 수 있습니다.

### 플러그인 개발 방법

1. **crypto_plugin 인터페이스 구현**:
```cpp
class my_crypto_plugin : public experiment::crypto::crypto_plugin {
public:
    std::string get_plugin_name() const override { return "my_plugin"; }
    std::string get_plugin_version() const override { return "1.0.0"; }
    bool initialize() override { /* 초기화 로직 */ return true; }
    void shutdown() override { /* 정리 로직 */ }

    // 원하는 알고리즘 구현
    std::shared_ptr<hash_interface> create_hash(const std::string& alg) override {
        if (alg == "MY_CUSTOM_HASH") {
            return std::make_shared<my_custom_hash>();
        }
        return nullptr;
    }
    // ... 다른 카테고리들
};
```

2. **create_plugin 함수 export**:
```cpp
extern "C" experiment::crypto::crypto_plugin* create_plugin() {
    return new my_crypto_plugin();
}
```

3. **공유 라이브러리로 빌드**:
```cmake
add_library(my_crypto_plugin SHARED my_crypto_plugin.cpp)
target_link_libraries(my_crypto_plugin experiment_crypto)
```

4. **설정 파일에 등록**:
```json
{
    "plugins": [
        {
            "name": "my_crypto_plugin",
            "path": "./plugins/libmy_crypto_plugin.so",
            "enabled": true
        }
    ]
}
```

### 플러그인 사용 예제

```cpp
#include "experiment/crypto/crypto_factory.hpp"

// 플러그인 로드
auto& factory = experiment::crypto::crypto_factory::get_instance();
factory.load_config("config.json"); // 설정 파일에 플러그인 지정됨

// 플러그인에서 제공하는 알고리즘 자동 사용
auto suite = factory.get_active_suite();
auto hash = suite->get_hash(); // 플러그인 알고리즘이 우선 사용됨
```

### 샘플 플러그인

`plugins/custom_crypto_plugin.cpp` - SHA3 해시 알고리즘을 제공하는 예제 플러그인

## 현재 구현 상태

### ✅ 구현 완료
- 설정 파일 로드/저장 시스템
- 6가지 카테고리의 인터페이스 정의
- 동적 플러그인 로딩/언로딩 시스템
- 기본 암호화 스위트들
- vSomeIP 설정 시스템 연동
- 플러그인 우선 알고리즘 선택

### ⚠️ 부분 구현
- 키 교환, 데이터 보호, 서명: 기존 vSomeIP TLS와 매핑됨
- 키 유도, 해시, 메시지 인증: 로깅만 구현 (OpenSSL 확장 필요)
- 샘플 플러그인: SHA3 해시만 구현

### 🔄 향후 확장 필요
- 실제 OpenSSL 커스터마이징
- 성능 벤치마킹
- 다양한 알고리즘 조합 테스트

## 테스트 실행

```bash
cd build
./crypto_test
```

## 주의사항

현재 이 프레임워크는 실험용이며, 프로덕션 환경에서는 추가 검증이 필요합니다. 특히 키 유도, 해시, 메시지 인증 카테고리의 실제 OpenSSL 구현은 아직 완료되지 않았습니다.
