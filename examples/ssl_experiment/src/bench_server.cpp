#include <vsomeip/vsomeip.hpp>
#include "experiment/crypto/crypto_factory.hpp"
#include <chrono>
#include <ctime>
#include <iostream>
#include <cstring>
#include <vector>

using clock_type = std::chrono::steady_clock;

static std::shared_ptr<vsomeip::application> app;
static constexpr vsomeip::service_t SERVICE = 0x9001;
static constexpr vsomeip::instance_t INSTANCE = 0x0001;
static constexpr vsomeip::method_t METHOD = 0x0001;

struct timestamps_t {
    uint64_t t_recv_in;
    uint64_t t_before_resp;
    uint64_t cpu_ns; // server CPU time consumed between recv and before_resp
};

// --- experiment crypto (optional) ---
static bool g_use_app_crypto = false;
static std::shared_ptr<experiment::crypto::crypto_suite> g_suite;
static std::shared_ptr<experiment::crypto::data_protection_interface> g_dp;
static std::shared_ptr<experiment::crypto::key_derivation_interface> g_kdf;
static std::vector<std::uint8_t> g_key;
static std::uint64_t g_nonce_counter = 1;

static std::vector<std::uint8_t> make_nonce12(std::uint64_t counter) {
    std::vector<std::uint8_t> n(12, 0);
    for (int i = 0; i < 8; ++i) n[11 - i] = static_cast<std::uint8_t>((counter >> (8 * i)) & 0xFF);
    return n;
}

static void setup_experiment_crypto() {
    const char* cfg = std::getenv("EXP_CRYPTO_CONFIG");
    const char* use = std::getenv("EXP_APP_CRYPTO");
    g_use_app_crypto = (use && std::string(use) == "1");
    if (!cfg) return;
    auto& f = experiment::crypto::crypto_factory::get_instance();
    if (!f.load_config(cfg)) return;
    f.apply_to_environment("127.0.0.1", 30601);
    g_suite = f.get_active_suite();
    if (!g_suite) return;
    g_dp = g_suite->get_data_protection();
    g_kdf = g_suite->get_key_derivation();
    if (!g_use_app_crypto || !g_dp || !g_kdf) return;
    const std::string alg = g_dp->get_algorithm_name();
    std::size_t key_len = (alg.find("SPECK") != std::string::npos) ? 32 : 16;
    std::vector<std::uint8_t> ikm{'b','e','n','c','h','_','s','e','c','r','e','t'};
    std::vector<std::uint8_t> salt{'b','e','n','c','h','_','s','a','l','t'};
    std::vector<std::uint8_t> info(alg.begin(), alg.end());
    g_key = g_kdf->derive(ikm, salt, info, key_len);
}

static inline uint64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(clock_type::now().time_since_epoch()).count();
}

static inline uint64_t proc_cpu_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

void handle_request(const std::shared_ptr<vsomeip::message> &request) {
    timestamps_t ts{};
    ts.t_recv_in = now_ns();
    uint64_t cpu_start = proc_cpu_ns();

    // Echo payload back and attach server timing in the beginning
    auto req_pl = request->get_payload();
    const auto len = req_pl->get_length();
    const auto data_ptr = req_pl->get_data();

    // optional decrypt
    std::vector<std::uint8_t> client_data(data_ptr, data_ptr + len);
    if (g_use_app_crypto && g_dp && !g_key.empty() && client_data.size() > 12 + 16) {
        std::vector<std::uint8_t> nonce(client_data.begin(), client_data.begin() + 12);
        std::vector<std::uint8_t> ct(client_data.begin() + 12, client_data.end());
        auto pt = g_dp->open(g_key, nonce, {}, ct);
        if (!pt.empty()) client_data.swap(pt);
    }

    std::vector<vsomeip::byte_t> out;
    out.resize(sizeof(timestamps_t) + client_data.size());
    std::memcpy(out.data(), &ts, sizeof(ts));
    if (!client_data.empty()) std::memcpy(out.data() + sizeof(timestamps_t), client_data.data(), client_data.size());

    auto resp = vsomeip::runtime::get()->create_response(request);
    ts.t_before_resp = now_ns();
    ts.cpu_ns = proc_cpu_ns() - cpu_start;
    std::memcpy(out.data(), &ts, sizeof(ts));

    // optional encrypt
    if (g_use_app_crypto && g_dp && !g_key.empty()) {
        auto nonce = make_nonce12(++g_nonce_counter);
        auto ct = g_dp->seal(g_key, nonce, {}, std::vector<std::uint8_t>(out.begin(), out.end()));
        if (!ct.empty()) {
            std::vector<vsomeip::byte_t> frame;
            frame.reserve(nonce.size() + ct.size());
            frame.insert(frame.end(), nonce.begin(), nonce.end());
            frame.insert(frame.end(), ct.begin(), ct.end());
            out.swap(frame);
        }
    }
    auto pl = vsomeip::runtime::get()->create_payload();
    pl->set_data(out);
    resp->set_payload(pl);
    app->send(resp);
}

void on_state(vsomeip::state_type_e state) {
    if (state == vsomeip::state_type_e::ST_REGISTERED) {
        app->offer_service(SERVICE, INSTANCE);
    }
}

int main() {
    setup_experiment_crypto();
    app = vsomeip::runtime::get()->create_application("bench_server");
    if (!app->init()) return 1;
    app->register_state_handler(on_state);
    app->register_message_handler(SERVICE, INSTANCE, METHOD, handle_request);
    app->start();
    return 0;
}

