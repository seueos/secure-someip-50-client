#include <vsomeip/vsomeip.hpp>
#include "experiment/crypto/crypto_factory.hpp"
#include <chrono>
#include <cstring>
#include <iostream>
#include <numeric>
#include <vector>
#include <cstdio>
#include <unistd.h>

using clock_type = std::chrono::steady_clock;

static std::shared_ptr<vsomeip::application> app;
static constexpr vsomeip::service_t SERVICE = 0x9001;
static constexpr vsomeip::instance_t INSTANCE = 0x0001;
static constexpr vsomeip::method_t METHOD = 0x0001;

// Configurable via env:
// BENCH_START_SIZE_KB (default 1), BENCH_MAX_SIZE_KB (default 1024), BENCH_MSGS_PER_SIZE (default 100), BENCH_CLIENTS (default 1)
static std::size_t env_start_kb() {
    const char* v = std::getenv("BENCH_START_SIZE_KB");
    if (!v) return 1;
    long x = std::strtol(v, nullptr, 10);
    return x > 0 ? static_cast<std::size_t>(x) : 1;
}
static std::size_t env_max_kb() {
    const char* v = std::getenv("BENCH_MAX_SIZE_KB");
    if (!v) return 1024;
    long x = std::strtol(v, nullptr, 10);
    return x > 0 ? static_cast<std::size_t>(x) : 1024;
}
static int env_msgs_per_size() {
    const char* v = std::getenv("BENCH_MSGS_PER_SIZE");
    if (!v) return 100;
    long x = std::strtol(v, nullptr, 10);
    return x > 0 ? static_cast<int>(x) : 100;
}
static int env_clients() {
    const char* v = std::getenv("BENCH_CLIENTS");
    if (!v) return 1;
    long x = std::strtol(v, nullptr, 10);
    return x > 0 ? static_cast<int>(x) : 1;
}

// CPU/mem measurement (Linux /proc)
static long g_clk_hz = 100;
static uint64_t g_size_begin_ns = 0;
static unsigned long long g_cpu_ticks_begin = 0;

static unsigned long long read_self_cpu_ticks() {
    FILE* f = std::fopen("/proc/self/stat", "r");
    if (!f) return 0;
    char buf[4096];
    size_t n = std::fgets(buf, sizeof(buf), f) ? std::strlen(buf) : 0;
    std::fclose(f);
    if (n == 0) return 0;
    char* rp = std::strrchr(buf, ')');
    if (!rp) return 0;
    char* p = rp + 2;
    int field = 3;
    unsigned long long utime = 0, stime = 0;
    for (; field <= 15 && p; ++field) {
        char* next = std::strchr(p, ' ');
        if (field == 14) utime = std::strtoull(p, nullptr, 10);
        if (field == 15) stime = std::strtoull(p, nullptr, 10);
        if (!next) break;
        p = next + 1;
    }
    return utime + stime;
}

static double read_self_mem_pct() {
    long page_size = sysconf(_SC_PAGESIZE);
    FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f) return 0.0;
    unsigned long rss_pages = 0, dummy = 0;
    int rc = std::fscanf(f, "%lu %lu", &dummy, &rss_pages);
    std::fclose(f);
    if (rc != 2) return 0.0;
    unsigned long long rss_bytes = static_cast<unsigned long long>(rss_pages) * static_cast<unsigned long long>(page_size);
    FILE* m = std::fopen("/proc/meminfo", "r");
    if (!m) return 0.0;
    char key[64]; unsigned long long kbytes = 0;
    while (std::fscanf(m, "%63s %llu kB", key, &kbytes) == 2) {
        if (std::strcmp(key, "MemTotal:") == 0) break;
    }
    std::fclose(m);
    unsigned long long total_bytes = kbytes * 1024ULL;
    if (total_bytes == 0) return 0.0;
    return (static_cast<double>(rss_bytes) / static_cast<double>(total_bytes)) * 100.0;
}

struct timestamps_t {
    uint64_t t_recv_in;      // server received
    uint64_t t_before_resp;  // server right before send
    uint64_t cpu_ns;         // server CPU time spent
};

static inline uint64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(clock_type::now().time_since_epoch()).count();
}

static std::size_t current_size = 1024; // bytes
static std::size_t max_size = 10 * 1024 * 1024; // 10 MiB
static int messages_per_size = 100;

static uint64_t t_client_send = 0;
static int sent_count = 0;
static std::vector<uint64_t> rtts_ns;
static std::vector<uint64_t> server_proc_ns;
static std::vector<uint64_t> server_que_ns;

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

void send_one() {
    if (sent_count == 0) {
        g_size_begin_ns = now_ns();
        g_cpu_ticks_begin = read_self_cpu_ticks();
    }
    auto req = vsomeip::runtime::get()->create_request();
    req->set_service(SERVICE);
    req->set_instance(INSTANCE);
    req->set_method(METHOD);
    std::vector<vsomeip::byte_t> payload(current_size, 0xAB);
    if (g_use_app_crypto && g_dp && !g_key.empty()) {
        auto nonce = make_nonce12(++g_nonce_counter);
        std::vector<std::uint8_t> pt(payload.begin(), payload.end());
        auto ct = g_dp->seal(g_key, nonce, {}, pt);
        if (!ct.empty()) {
            std::vector<vsomeip::byte_t> frame;
            frame.reserve(nonce.size() + ct.size());
            frame.insert(frame.end(), nonce.begin(), nonce.end());
            frame.insert(frame.end(), ct.begin(), ct.end());
            payload.swap(frame);
        }
    }
    auto pl = vsomeip::runtime::get()->create_payload();
    pl->set_data(payload);
    req->set_payload(pl);
    t_client_send = now_ns();
    app->send(req);
}

void on_response(const std::shared_ptr<vsomeip::message> &resp) {
    auto t_recv = now_ns();
    auto pl = resp->get_payload();
    std::vector<std::uint8_t> data(pl->get_data(), pl->get_data() + pl->get_length());
    if (g_use_app_crypto && g_dp && !g_key.empty() && data.size() > 12 + 16) {
        std::vector<std::uint8_t> nonce(data.begin(), data.begin() + 12);
        std::vector<std::uint8_t> ct(data.begin() + 12, data.end());
        auto pt = g_dp->open(g_key, nonce, {}, ct);
        if (!pt.empty()) data.swap(pt);
    }
    if (data.size() < sizeof(timestamps_t)) return;
    timestamps_t ts{};
    std::memcpy(&ts, data.data(), sizeof(ts));
    uint64_t rtt = t_recv - t_client_send;
    uint64_t s_proc = ts.t_before_resp - ts.t_recv_in;
    uint64_t s_queue = ts.t_recv_in - t_client_send; // includes network + vsomeip queueing
    rtts_ns.push_back(rtt);
    server_proc_ns.push_back(s_proc);
    server_que_ns.push_back(s_queue);

    if (++sent_count < messages_per_size) {
        send_one();
        return;
    }

    auto avg = [](const std::vector<uint64_t>& v){
        return v.empty() ? 0ULL : std::accumulate(v.begin(), v.end(), 0ULL) / static_cast<uint64_t>(v.size());
    };
    // CPU% over the size window
    unsigned long long cpu_ticks_end = read_self_cpu_ticks();
    uint64_t elapsed_ns = t_recv - g_size_begin_ns;
    double elapsed_s = static_cast<double>(elapsed_ns) / 1e9;
    double cpu_pct = 0.0;
    if (elapsed_s > 0.0) {
        double cpu_sec = static_cast<double>(cpu_ticks_end - g_cpu_ticks_begin) / static_cast<double>(g_clk_hz);
        cpu_pct = (cpu_sec / elapsed_s) * 100.0; // percent of a single core
    }
    double mem_pct = read_self_mem_pct();
    int clients = env_clients();
    std::cout << "size_kb=" << (current_size/1024)
              << " clients=" << clients
              << " rtt_avg_ns=" << avg(rtts_ns)
              << " srv_proc_avg_ns=" << avg(server_proc_ns)
              << " srv_queue_est_ns=" << avg(server_que_ns)
              << " cpu_pct=" << cpu_pct
              << " mem_pct=" << mem_pct
              << std::endl;

    rtts_ns.clear(); server_proc_ns.clear(); server_que_ns.clear();
    sent_count = 0;
    if (current_size < max_size) {
        std::size_t next = current_size * 2;
        if (next > max_size) next = max_size;
        current_size = next;
        send_one();
    } else {
        std::cout << "benchmark done" << std::endl;
        app->stop();
    }
}

void on_state(vsomeip::state_type_e state) {
    if (state == vsomeip::state_type_e::ST_REGISTERED) {
        app->request_service(SERVICE, INSTANCE);
    }
}

void on_availability(vsomeip::service_t s, vsomeip::instance_t i, bool av) {
    if (s==SERVICE && i==INSTANCE && av) {
        current_size = 1024; sent_count = 0; rtts_ns.clear(); server_proc_ns.clear(); server_que_ns.clear();
        send_one();
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    setup_experiment_crypto();
    g_clk_hz = sysconf(_SC_CLK_TCK);
    std::size_t start_kb = env_start_kb();
    std::size_t max_kb = env_max_kb();
    current_size = start_kb * 1024;
    max_size = max_kb * 1024;
    messages_per_size = env_msgs_per_size();
    app = vsomeip::runtime::get()->create_application("bench_client");
    if (!app->init()) return 1;
    app->register_state_handler(on_state);
    app->register_availability_handler(SERVICE, INSTANCE, on_availability);
    app->register_message_handler(SERVICE, INSTANCE, METHOD, on_response);
    app->start();
    return 0;
}

