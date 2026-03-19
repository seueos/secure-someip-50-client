#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXDIR="$ROOT/examples/ssl_experiment"
SSLDIR="$ROOT/examples/ssl"

build_if_needed() {
  if [ ! -x "$ROOT/build/examples/ssl_experiment/bench_server" ]; then
    mkdir -p "$ROOT/build"
    cd "$ROOT/build"
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j
  fi
}

prepare_rsa() {
  pushd "$SSLDIR" >/dev/null
  ALG=RSA ./gen-certs.sh
  popd >/dev/null
}

prepare_ecdsa() {
  pushd "$SSLDIR" >/dev/null
  ALG=ECDSA ./gen-certs.sh
  popd >/dev/null
}

run_one() {
  local name="$1" json="$2"
  echo "=== $name ==="
  pushd "$ROOT/build/examples/ssl_experiment" >/dev/null
  VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME=bench_server ./bench_server >/tmp/bench_server.log 2>&1 &
  srv=$!
  sleep 1
  VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME=bench_client ./bench_client | tee "/tmp/${name}_client.txt"
  kill "$srv" || true
  wait "$srv" 2>/dev/null || true
  popd >/dev/null
}

# 1) SSL default: keep OpenSSL defaults (TLS1.2/1.3 allowed, cipher/groups default)
run_default_ssl() {
  unset VSOMEIP_TLS_MIN_VERSION VSOMEIP_TLS_MAX_VERSION VSOMEIP_TLS_CIPHERS VSOMEIP_TLS_CIPHERSUITES13 VSOMEIP_TLS_GROUPS VSOMEIP_TLS_SIGALGS VSOMEIP_TLS_EARLY_DATA || true
  run_one "ssl_default" "with_ssl.json"
}

# 2) Image profile: TLS1.3 + AES-GCM + groups/sigalgs
run_image_profile() {
  export VSOMEIP_TLS_MIN_VERSION=TLS1_3
  export VSOMEIP_TLS_MAX_VERSION=TLS1_3
  export VSOMEIP_TLS_CIPHERSUITES13="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
  export VSOMEIP_TLS_GROUPS="X25519:P-256"
  export VSOMEIP_TLS_SIGALGS="ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256"
  export VSOMEIP_TLS_EARLY_DATA=0
  run_one "ssl_image" "with_ssl.json"
}

build_if_needed
# Default certs (RSA) for default profile
prepare_rsa
run_default_ssl
# ECDSA certs for image profile (matches ECDSA-P256)
prepare_ecdsa
run_image_profile

# Generate report (labels: ssl_default vs ssl_image)
python3 "$EXDIR/report_ssl_compare.py" "ssl_default" "/tmp/ssl_default_client.txt" "ssl_image" "/tmp/ssl_image_client.txt"
