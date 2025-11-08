cmake_minimum_required(VERSION 3.13)
project(experiment)

# C++17 표준 사용
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# nlohmann/json 찾기 (외부 라이브러리)
find_package(nlohmann_json REQUIRED)

# 인클루드 디렉토리 설정
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# 소스 파일들
set(CONFIG_SOURCES
    src/config/crypto_config_loader.cpp
)

set(CRYPTO_SOURCES
    src/crypto/crypto_factory.cpp
)

set(TEST_SOURCES
    test/crypto_test.cpp
)

set(EXAMPLE_SOURCES
    examples/test_combinations.cpp
)

# 설정 라이브러리
add_library(experiment_config STATIC ${CONFIG_SOURCES})
target_link_libraries(experiment_config nlohmann_json::nlohmann_json)

# 암호화 라이브러리
add_library(experiment_crypto STATIC ${CRYPTO_SOURCES})
target_link_libraries(experiment_crypto experiment_config)

# dl 라이브러리 링크 (플러그인 로딩용)
if(NOT MSVC)
    target_link_libraries(experiment_crypto ${CMAKE_DL_LIBS})
endif()

# 플러그인 서브디렉토리
add_subdirectory(plugins)

# 테스트 실행 파일
add_executable(crypto_test ${TEST_SOURCES})
target_link_libraries(crypto_test experiment_crypto)

# 예제 실행 파일
add_executable(test_combinations ${EXAMPLE_SOURCES})
target_link_libraries(test_combinations experiment_crypto)

# 테스트 추가
enable_testing()
add_test(NAME crypto_test COMMAND crypto_test)
add_test(NAME test_combinations COMMAND test_combinations)

# 설치 규칙 (옵션)
install(TARGETS experiment_config experiment_crypto
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY include/
        DESTINATION include/experiment)

# 컴파일 옵션
if(MSVC)
    target_compile_options(experiment_config PRIVATE /W4)
    target_compile_options(experiment_crypto PRIVATE /W4)
    target_compile_options(crypto_test PRIVATE /W4)
else()
    target_compile_options(experiment_config PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(experiment_crypto PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(crypto_test PRIVATE -Wall -Wextra -Wpedantic)
endif()
