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

run_case() {
  local label="$1" json="$2" clients="$3" start_kb="$4" max_kb="$5" msgs="$6"
  echo "=== $label (clients=$clients, ${start_kb}KB->${max_kb}KB, msgs=${msgs}) ==="
  pushd "$ROOT/build/examples/ssl_experiment" >/dev/null
  VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME=bench_server ./bench_server >/tmp/bench_server.log 2>&1 &
  srv=$!
  sleep 1
  out="/tmp/${label}_c${clients}.txt"
  : > "$out"
  pids=()
  for i in $(seq 1 "$clients"); do
    BENCH_CLIENTS="$clients" BENCH_START_SIZE_KB="$start_kb" BENCH_MAX_SIZE_KB="$max_kb" BENCH_MSGS_PER_SIZE="$msgs" \
      VSOMEIP_CONFIGURATION="$EXDIR/$json" VSOMEIP_APPLICATION_NAME="bench_client_$i" ./bench_client >>"$out" 2>&1 &
    pids+=($!)
  done
  for p in "${pids[@]}"; do
    wait "$p" || true
  done
  kill "$srv" || true
  wait "$srv" 2>/dev/null || true
  popd >/dev/null
  echo "Result: $out"
}

build_if_needed

prepare_ecdsa

# Parameters
CLIENTS_LIST=${CLIENTS_LIST:-"1 2 4"}
START_KB=${START_KB:-1}
MAX_KB=${MAX_KB:-1024}
MSGS_PER_SIZE=${MSGS_PER_SIZE:-100}

# TLS profile (can be toggled before calling this script)
: "${VSOMEIP_TLS_MIN_VERSION:=TLS1_3}"
: "${VSOMEIP_TLS_MAX_VERSION:=TLS1_3}"
: "${VSOMEIP_TLS_CIPHERSUITES13:=TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384}"
: "${VSOMEIP_TLS_GROUPS:=X25519:P-256}"
: "${VSOMEIP_TLS_SIGALGS:=ed25519:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256}"
: "${VSOMEIP_TLS_EARLY_DATA:=0}"

for c in $CLIENTS_LIST; do
  run_case "tls_profile" "with_ssl.json" "$c" "$START_KB" "$MAX_KB" "$MSGS_PER_SIZE"
done

echo "All runs done."


