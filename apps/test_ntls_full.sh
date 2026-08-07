#!/usr/bin/env bash
set -u

for arg in "$@"; do
    case "$arg" in
        *=*)
            export "$arg"
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

export OPENSSL_CONF="${OPENSSL_CONF:-$SCRIPT_DIR/openssl.cnf}"
export SDF_LIB_PATH="${SDF_LIB_PATH:-$SCRIPT_DIR/libbyzk0018.so}"
export BYZK0018_SKIP_OPENSSL_PROVIDER_INIT="${BYZK0018_SKIP_OPENSSL_PROVIDER_INIT:-1}"
export SDF_MODULE_PASSWORD="${SDF_MODULE_PASSWORD:-88888888}"
export SDF_USE_LOADMODULE="${SDF_USE_LOADMODULE:-1}"

OSSL="${OSSL:-openssl}"

PASS=0
FAIL=0
NUM=0
OUTDIR="$PWD"
CERTS="${CERTS:-./certs/sm2}"
CAFILE="${CAFILE:-$CERTS/sm2_chain-ca.crt}"
SERVER_CERT_PROFILE="${SERVER_CERT_PROFILE:-sm2}"
CLIENT_CERT_PROFILE="${CLIENT_CERT_PROFILE:-sm2}"

SERVER_SIGN_CERT="${SERVER_SIGN_CERT:-$CERTS/sm2_server_sign.crt}"
SERVER_ENC_CERT="${SERVER_ENC_CERT:-$CERTS/sm2_server_enc.crt}"
SERVER_SIGN_KEY="${SERVER_SIGN_KEY:-$CERTS/sm2_server_sign.key}"
SERVER_ENC_KEY="${SERVER_ENC_KEY:-$CERTS/sm2_server_enc.key}"

CLIENT_SIGN_CERT="${CLIENT_SIGN_CERT:-$CERTS/sm2_client_sign.crt}"
CLIENT_ENC_CERT="${CLIENT_ENC_CERT:-$CERTS/sm2_client_enc.crt}"
CLIENT_SIGN_KEY="${CLIENT_SIGN_KEY:-$CERTS/sm2_client_sign.key}"
CLIENT_ENC_KEY="${CLIENT_ENC_KEY:-$CERTS/sm2_client_enc.key}"

SERVER_HW_SIGN_IDX="${SERVER_HW_SIGN_IDX:-1}"
SERVER_HW_ENC_IDX="${SERVER_HW_ENC_IDX:-1}"
CLIENT_HW_SIGN_IDX="${CLIENT_HW_SIGN_IDX:-2}"
CLIENT_HW_ENC_IDX="${CLIENT_HW_ENC_IDX:-2}"

apply_cert_profile() {
    side="$1"
    profile="$2"

    case "$profile" in
        sm2|"")
            ;;
        rsa2048|rsa3072|rsa4096)
            echo "FAIL: test_ntls_full only supports SM2 certificate profiles for NTLS; got ${side} profile '$profile'"
            exit 1
            ;;
        *)
            echo "FAIL: unknown ${side} certificate profile '$profile'"
            exit 1
            ;;
    esac
}

apply_cert_profile server "$SERVER_CERT_PROFILE"
apply_cert_profile client "$CLIENT_CERT_PROFILE"

if [ "${IMPORT_KEYS:-1}" != "0" ]; then
    echo "[CMD] $SCRIPT_DIR/import_sdf_keys.sh IMPORT_GROUP=sm2"
    "$SCRIPT_DIR/import_sdf_keys.sh" IMPORT_GROUP=sm2 || exit 1
fi

cleanup_all() {
    pkill -f "$(basename "$OSSL")" >/dev/null 2>&1 || true
    rm -f yj.db-shm yj.db-wal
}

wait_seconds() {
    sleep "$1"
}

print_summary() {
    echo ""
    echo "================================================================"
    echo "  SUMMARY: PASS=$PASS / $NUM, FAIL=$FAIL / $NUM"
    echo "================================================================"
}

run_handshake() {
    local port="$1"
    local cipher="$2"
    local server_key_type="$3"
    local client_key_type="$4"
    local server_log="$OUTDIR/ntls_svr_${port}.txt"
    local client_log="$OUTDIR/ntls_cli_${port}.txt"
    local server_cmd
    local client_cmd
    local timeout_count=0
    local server_pid

    server_cmd="$OSSL s_server -ntls -enable_ntls -accept $port"
    if [ "$server_key_type" = "sw" ]; then
        server_cmd="$server_cmd -sign_cert $SERVER_SIGN_CERT -enc_cert $SERVER_ENC_CERT -sign_key $SERVER_SIGN_KEY -enc_key $SERVER_ENC_KEY"
    else
        server_cmd="$server_cmd -sign_cert $SERVER_SIGN_CERT -enc_cert $SERVER_ENC_CERT -sign_key 'sdf:key=${SERVER_HW_SIGN_IDX};type=sign' -enc_key 'sdf:key=${SERVER_HW_ENC_IDX};type=enc' -provider sdfprov -provider default"
    fi
    server_cmd="$server_cmd -www -CAfile $CAFILE -cipher $cipher"

    client_cmd="$OSSL s_client -ntls -enable_ntls -connect 127.0.0.1:$port"
    if [ "$client_key_type" = "sw" ]; then
        client_cmd="$client_cmd -sign_cert $CLIENT_SIGN_CERT -enc_cert $CLIENT_ENC_CERT -sign_key $CLIENT_SIGN_KEY -enc_key $CLIENT_ENC_KEY"
    else
        client_cmd="$client_cmd -sign_cert $CLIENT_SIGN_CERT -enc_cert $CLIENT_ENC_CERT -sign_key 'sdf:key=${CLIENT_HW_SIGN_IDX};type=sign' -enc_key 'sdf:key=${CLIENT_HW_ENC_IDX};type=enc' -provider sdfprov -provider default"
    fi
    client_cmd="$client_cmd -CAfile $CAFILE -cipher $cipher"

    rm -f "$server_log" "$client_log"

    echo "[CMD][server] $server_cmd"
    sh -c "$server_cmd" >"$server_log" 2>&1 &
    server_pid=$!

    if [ "$server_key_type" = "hw" ]; then
        wait_seconds 4
    else
        wait_seconds 2
    fi

    echo "[CMD][client] printf 'Q\\n' | $client_cmd"
    sh -c "printf 'Q\n' | $client_cmd" >"$client_log" 2>&1 &

    while [ $timeout_count -lt 15 ]; do
        if grep -q "Cipher is" "$client_log" 2>/dev/null; then
            break
        fi
        timeout_count=$((timeout_count + 1))
        wait_seconds 1
    done

    if ! grep -q "Cipher is" "$client_log" 2>/dev/null; then
        cleanup_all
        echo "    [TIMEOUT] client wait timed out; forced termination"
    fi

    if grep -Eq "Cipher is ECC-SM2-SM4-CBC-SM3|Cipher is ECDHE-SM2-SM4-CBC-SM3" "$client_log" 2>/dev/null; then
        echo "    [PASS]"
        grep "Cipher is" "$client_log" | sed 's/^/    /'
        grep "Protocol" "$client_log" | sed 's/^/    /'
        PASS=$((PASS + 1))
    else
        echo "    [FAIL]"
        grep -i "error" "$client_log" 2>/dev/null | sed 's/^/    Client: /'
        grep -i "error" "$server_log" 2>/dev/null | sed 's/^/    Server: /'
        FAIL=$((FAIL + 1))
    fi

    if kill -0 "$server_pid" >/dev/null 2>&1; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" 2>/dev/null || true
    fi
    cleanup_all

    if [ "$server_key_type" = "hw" ] || [ "$client_key_type" = "hw" ]; then
        wait_seconds 3
    else
        wait_seconds 1
    fi
}

trap 'cleanup_all' EXIT

echo ""
echo "================================================================"
echo "  NTLS SM2 Full Matrix Test"
echo "  2 cipher suites x 4 key combinations = 8 scenarios"
echo "================================================================"

cleanup_all
wait_seconds 2

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECC-SM2-SM4-CBC-SM3 | Svr:SW | Cli:SW"
run_handshake 25101 ECC-SM2-SM4-CBC-SM3 sw sw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECC-SM2-SM4-CBC-SM3 | Svr:HW | Cli:SW"
run_handshake 25102 ECC-SM2-SM4-CBC-SM3 hw sw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECC-SM2-SM4-CBC-SM3 | Svr:SW | Cli:HW"
run_handshake 25103 ECC-SM2-SM4-CBC-SM3 sw hw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECC-SM2-SM4-CBC-SM3 | Svr:HW | Cli:HW"
run_handshake 25104 ECC-SM2-SM4-CBC-SM3 hw hw

echo ""
echo " [cooldown 5s - release SDF device resources]"
cleanup_all
wait_seconds 5

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECDHE-SM2-SM4-CBC-SM3 | Svr:SW | Cli:SW"
run_handshake 25105 ECDHE-SM2-SM4-CBC-SM3 sw sw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECDHE-SM2-SM4-CBC-SM3 | Svr:HW | Cli:SW"
run_handshake 25106 ECDHE-SM2-SM4-CBC-SM3 hw sw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECDHE-SM2-SM4-CBC-SM3 | Svr:SW | Cli:HW"
run_handshake 25107 ECDHE-SM2-SM4-CBC-SM3 sw hw

NUM=$((NUM + 1))
echo ""
echo " [$NUM] ECDHE-SM2-SM4-CBC-SM3 | Svr:HW | Cli:HW"
run_handshake 25108 ECDHE-SM2-SM4-CBC-SM3 hw hw

print_summary
[ "$FAIL" -eq 0 ]
