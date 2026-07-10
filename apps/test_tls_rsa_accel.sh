#!/usr/bin/env bash
set -u

for arg in "$@"; do
    case "$arg" in
        *=*) export "$arg" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OSSL="$SCRIPT_DIR/openssl"
CERTS="../test/certs"
OPENSSL_CONF="${OPENSSL_CONF:-$SCRIPT_DIR/openssl.cnf}"
TMP="${TMP:-/tmp/tls_rsa_accel}"
mkdir -p "$TMP"

RSA_SIGN_IDX="${RSA_SIGN_IDX:-0}"
RSA_ENC_IDX="${RSA_ENC_IDX:-0}"
RSA_SIGN_CERT="${RSA_SIGN_CERT:-$CERTS/server-rsa-sign.crt}"
RSA_ENC_CERT="${RSA_ENC_CERT:-$CERTS/server-rsa-enc.crt}"
TLS_VERSION="${TLS_VERSION:--tls1_2}"
ECDHE_CIPHER="${ECDHE_CIPHER:-ECDHE-RSA-AES128-GCM-SHA256}"
RSA_CIPHER="${RSA_CIPHER:-AES128-SHA}"
RSA_SIGALGS="${RSA_SIGALGS:-}"
RSA_SIGALGS_COMPAT="${RSA_SIGALGS_COMPAT:-rsa_pkcs1_sha256}"
PORT_SIGN="${PORT_SIGN:-25203}"
PORT_DEC="${PORT_DEC:-25202}"

PASS=0
FAIL=0

cleanup_port() {
    pkill -f "openssl s_server" >/dev/null 2>&1 || true
    pkill -f "openssl s_client" >/dev/null 2>&1 || true
    sleep 1
}

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

wait_client_result() {
    local file="$1"
    local i
    for i in $(seq 1 15); do
        sleep 1
        if grep -q "Cipher is" "$file" 2>/dev/null; then
            return 0
        fi
    done
    return 0
}

echo "============================================================"
echo " TLS RSA Acceleration Test"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo " RSA_SIGN_IDX=$RSA_SIGN_IDX  RSA_ENC_IDX=$RSA_ENC_IDX"
echo "============================================================"

run_ecdhe_sign() {
    local mode="$1"
    local sigalgs="$2"
    local port="$3"
    local sf="$TMP/tls_rsa_sign_${mode}_server.txt"
    local cf="$TMP/tls_rsa_sign_${mode}_client.txt"

    echo
    echo "==== ECDHE-RSA server HW-sign ($mode) ===="
    cleanup_port

    if [ -n "$sigalgs" ]; then
        OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_server -accept "$port" "$TLS_VERSION" \
            -cipher "$ECDHE_CIPHER" -sigalgs "$sigalgs" \
            -cert "$RSA_SIGN_CERT" -key "sdf:rsa:$RSA_SIGN_IDX:sign" \
            -provider sdfprov -provider default -www >"$sf" 2>&1 &
        SPID=$!
        sleep 2
        printf 'Q\n' | OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_client -connect "127.0.0.1:$port" "$TLS_VERSION" \
            -cipher "$ECDHE_CIPHER" -sigalgs "$sigalgs" >"$cf" 2>&1 || true
    else
        OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_server -accept "$port" "$TLS_VERSION" \
            -cipher "$ECDHE_CIPHER" \
            -cert "$RSA_SIGN_CERT" -key "sdf:rsa:$RSA_SIGN_IDX:sign" \
            -provider sdfprov -provider default -www >"$sf" 2>&1 &
        SPID=$!
        sleep 2
        printf 'Q\n' | OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_client -connect "127.0.0.1:$port" "$TLS_VERSION" \
            -cipher "$ECDHE_CIPHER" >"$cf" 2>&1 || true
    fi

    wait_client_result "$cf"
    if grep -q "Cipher is $ECDHE_CIPHER" "$cf"; then
        pass "ECDHE-RSA server HW-sign ($mode)"
        grep -E "Protocol|Cipher is" "$cf" || true
    else
        fail "ECDHE-RSA server HW-sign ($mode)"
        grep -i "error" "$cf" || true
        grep -i "error" "$sf" || true
    fi
    kill "$SPID" >/dev/null 2>&1 || true
    cleanup_port
}

run_ecdhe_sign "default" "$RSA_SIGALGS" "$PORT_SIGN"
run_ecdhe_sign "compat" "$RSA_SIGALGS_COMPAT" "25205"

echo
echo "==== TLS_RSA server HW-decrypt ===="
cleanup_port
SF="$TMP/tls_rsa_dec_server.txt"
CF="$TMP/tls_rsa_dec_client.txt"
OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_server -accept "$PORT_DEC" "$TLS_VERSION" \
    -cipher "$RSA_CIPHER" \
    -cert "$RSA_ENC_CERT" -key "sdf:rsa:$RSA_ENC_IDX:enc" \
    -provider sdfprov -provider default -www >"$SF" 2>&1 &
SPID=$!
sleep 2
printf 'Q\n' | OPENSSL_CONF="$OPENSSL_CONF" "$OSSL" s_client -connect "127.0.0.1:$PORT_DEC" "$TLS_VERSION" \
    -cipher "$RSA_CIPHER" >"$CF" 2>&1 || true
wait_client_result "$CF"
if grep -q "Cipher is $RSA_CIPHER" "$CF"; then
    pass "TLS_RSA server HW-decrypt"
    grep -E "Protocol|Cipher is" "$CF" || true
else
    fail "TLS_RSA server HW-decrypt"
    grep -i "error" "$CF" || true
    grep -i "error" "$SF" || true
fi
kill "$SPID" >/dev/null 2>&1 || true
cleanup_port

echo
echo "============================================================"
echo " SUMMARY: PASS=$PASS FAIL=$FAIL"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
