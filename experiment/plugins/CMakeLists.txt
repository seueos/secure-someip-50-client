cmake_minimum_required(VERSION 3.13)
project(experiment_plugins)

# OpenSSL 찾기
find_package(OpenSSL REQUIRED)

# 플러그인 라이브러리들
add_library(custom_crypto_plugin SHARED custom_crypto_plugin.cpp)
target_link_libraries(custom_crypto_plugin experiment_crypto OpenSSL::Crypto)
target_include_directories(custom_crypto_plugin PRIVATE ../include)

add_library(ascon_speck_plugin SHARED ascon_speck_plugin.cpp)
target_link_libraries(ascon_speck_plugin experiment_crypto OpenSSL::Crypto)
target_include_directories(ascon_speck_plugin PRIVATE ../include)

# 설치
install(TARGETS custom_crypto_plugin
        LIBRARY DESTINATION lib/experiment/plugins)

install(TARGETS ascon_speck_plugin
        LIBRARY DESTINATION lib/experiment/plugins)

# 컴파일 옵션
if(MSVC)
    target_compile_options(custom_crypto_plugin PRIVATE /W4)
    target_compile_options(ascon_speck_plugin PRIVATE /W4)
else()
    target_compile_options(custom_crypto_plugin PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(ascon_speck_plugin PRIVATE -Wall -Wextra -Wpedantic)
endif()
