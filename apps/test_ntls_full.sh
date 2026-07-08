#!/usr/bin/env bash
set -u

export OPENSSL_CONF="${OPENSSL_CONF:-$(pwd)/openssl.cnf}"
export SDF_LIB_PATH="${SDF_LIB_PATH:-$(pwd)/libbyzk0018.so}"
export SDF_MODULE_PASSWORD="${SDF_MODULE_PASSWORD:-88888888}"
export SDF_USE_LOADMODULE="${SDF_USE_LOADMODULE:-1}"

if [ -x ./openssl ]; then
    OSSL=./openssl
elif [ -x ./openssl.exe ]; then
    OSSL=./openssl.exe
else
    echo "FAIL: cannot find ./openssl or ./openssl.exe"
    exit 1
fi

PASS=0
FAIL=0
NUM=0
OUTDIR="../ntls_out"
CERTS="../test/certs/sm2"
CAFILE="$CERTS/chain-ca.crt"

mkdir -p "$OUTDIR"

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
    local server_log="$OUTDIR/svr_${port}.txt"
    local client_log="$OUTDIR/cli_${port}.txt"
    local server_cmd
    local client_cmd
    local timeout_count=0
    local server_pid

    server_cmd="$OSSL s_server -ntls -enable_ntls -accept $port"
    if [ "$server_key_type" = "sw" ]; then
        server_cmd="$server_cmd -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt -sign_key $CERTS/server_sign.key -enc_key $CERTS/server_enc.key"
    else
        server_cmd="$server_cmd -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt -sign_key 'sdf:key=0;type=sign' -enc_key 'sdf:key=0;type=enc' -provider sdfprov -provider default"
    fi
    server_cmd="$server_cmd -www -CAfile $CAFILE -cipher $cipher"

    client_cmd="$OSSL s_client -ntls -enable_ntls -connect 127.0.0.1:$port"
    if [ "$client_key_type" = "sw" ]; then
        client_cmd="$client_cmd -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt -sign_key $CERTS/client_sign.key -enc_key $CERTS/client_enc.key"
    else
        client_cmd="$client_cmd -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt -sign_key 'sdf:key=1;type=sign' -enc_key 'sdf:key=1;type=enc' -provider sdfprov -provider default"
    fi
    client_cmd="$client_cmd -CAfile $CAFILE -cipher $cipher"

    rm -f "$server_log" "$client_log"

    sh -c "$server_cmd" >"$server_log" 2>&1 &
    server_pid=$!

    if [ "$server_key_type" = "hw" ]; then
        wait_seconds 4
    else
        wait_seconds 2
    fi

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
