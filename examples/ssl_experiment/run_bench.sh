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

prepare_ecdsa() {
  pushd "$SSLDIR" >/dev/null
  ALG=ECDSA ./gen-certs.sh
  popd >/dev/null
}

run_one() {
  local name="$1" json="$2"
  echo "=== $name ==="
  pushd "$ROOT/build/examples/ssl_experiment" >/dev/null
  # server
  VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME=bench_server ./bench_server >/tmp/bench_server.log 2>&1 &
  srv=$!
  sleep 1
  # client
  VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME=bench_client ./bench_client | tee "/tmp/${name}_client.txt"
  kill "$srv" || true
  wait "$srv" 2>/dev/null || true
  popd >/dev/null
}

summarize() {
  local file="$1"
  awk '{print $0}' "$file" | tail -n +1
}

build_if_needed
prepare_ecdsa

# Profile A: default (without SSL)
run_one "no_ssl" "without_ssl.json"

# Profile B: image TLS profile (with SSL settings)
export VSOMEIP_TLS_MIN_VERSION=TLS1_3
export VSOMEIP_TLS_MAX_VERSION=TLS1_3
export VSOMEIP_TLS_CIPHERSUITES13="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
export VSOMEIP_TLS_GROUPS="X25519:P-256"
export VSOMEIP_TLS_SIGALGS="ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256"
export VSOMEIP_TLS_EARLY_DATA=0
run_one "image_tls" "with_ssl.json"

echo "Done. Compare /tmp/no_ssl_client.txt vs /tmp/image_tls_client.txt"


