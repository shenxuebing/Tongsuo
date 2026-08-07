#!/usr/bin/env bash
set -u

for arg in "$@"; do
    case "$arg" in
        *=*) export "$arg" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ -x "$SCRIPT_DIR/openssl" ]; then
    OSSL="$SCRIPT_DIR/openssl"
elif [ -x "$SCRIPT_DIR/openssl.exe" ]; then
    OSSL="$SCRIPT_DIR/openssl.exe"
else
    echo "[FAIL] cannot find openssl in $SCRIPT_DIR"
    exit 1
fi

CERTS="${CERTS:-.}"
export OPENSSL_CONF="${OPENSSL_CONF:-$SCRIPT_DIR/openssl.cnf}"
TMP="${TMP:-/tmp/tls_rsa_accel}"
mkdir -p "$TMP"

# 密钥索引: 1=server RSA2048, 2=client RSA2048
SERVER_RSA_IDX="${SERVER_RSA_IDX:-1}"
CLIENT_RSA_IDX="${CLIENT_RSA_IDX:-2}"

RSA_CERTS_DIR="${RSA_CERTS_DIR:-$CERTS/rsa}"
RSA_SIGN_CERT="${RSA_SIGN_CERT:-$RSA_CERTS_DIR/rsa2048_sign.crt}"
RSA_SIGN_KEY="${RSA_SIGN_KEY:-$RSA_CERTS_DIR/rsa2048_sign.key}"
RSA_ENC_CERT="${RSA_ENC_CERT:-$RSA_CERTS_DIR/rsa2048_enc.crt}"
RSA_ENC_KEY="${RSA_ENC_KEY:-$RSA_CERTS_DIR/rsa2048_enc.key}"
CLIENT_SIGN_CERT="${CLIENT_SIGN_CERT:-$RSA_CERTS_DIR/client_sign.crt}"
CLIENT_SIGN_KEY="${CLIENT_SIGN_KEY:-$RSA_CERTS_DIR/client_sign.key}"
CLIENT_ENC_CERT="${CLIENT_ENC_CERT:-$RSA_CERTS_DIR/client_enc.crt}"
CLIENT_ENC_KEY="${CLIENT_ENC_KEY:-$RSA_CERTS_DIR/client_enc.key}"

TLS_VERSION="${TLS_VERSION:--tls1_2}"
ECDHE_CIPHER="${ECDHE_CIPHER:-ECDHE-RSA-AES128-GCM-SHA256}"
RSA_CIPHER="${RSA_CIPHER:-AES128-SHA}"
PORT_BASE="${PORT_BASE:-25210}"

PROV_SDF="-provider sdfprov -provider default"

PASS=0
FAIL=0
NUM=0

cleanup_port() {
    pkill -f "openssl s_server" >/dev/null 2>&1 || true
    pkill -f "openssl s_client" >/dev/null 2>&1 || true
    sleep 1
}

ok() { echo "    [PASS]"; PASS=$((PASS + 1)); }
no() { echo "    [FAIL]"; FAIL=$((FAIL + 1)); }

# ============================================================
# 测试前导入密钥到密码卡
# ============================================================
import_keys() {
    echo "==== Import RSA keys to device ===="
    # 先删除可能已有的密钥（忽略错误）
    "$OSSL" sdf -delsm2key -index "$SERVER_RSA_IDX" -type sign 2>/dev/null
    "$OSSL" sdf -delsm2key -index "$SERVER_RSA_IDX" -type enc  2>/dev/null
    "$OSSL" sdf -delsm2key -index "$CLIENT_RSA_IDX" -type sign 2>/dev/null
    "$OSSL" sdf -delsm2key -index "$CLIENT_RSA_IDX" -type enc  2>/dev/null

    # server RSA2048 签名+加密 -> 索引1
    echo "[CMD] $OSSL sdf -importrsakey -index $SERVER_RSA_IDX -type sign -inkey $RSA_SIGN_KEY"
    "$OSSL" sdf -importrsakey -index "$SERVER_RSA_IDX" -type sign -inkey "$RSA_SIGN_KEY" 2>/dev/null
    echo "[CMD] $OSSL sdf -importrsakey -index $SERVER_RSA_IDX -type enc -inkey $RSA_ENC_KEY"
    "$OSSL" sdf -importrsakey -index "$SERVER_RSA_IDX" -type enc  -inkey "$RSA_ENC_KEY"  2>/dev/null

    # client RSA2048 签名+加密 -> 索引2
    echo "[CMD] $OSSL sdf -importrsakey -index $CLIENT_RSA_IDX -type sign -inkey $CLIENT_SIGN_KEY"
    "$OSSL" sdf -importrsakey -index "$CLIENT_RSA_IDX" -type sign -inkey "$CLIENT_SIGN_KEY" 2>/dev/null
    echo "[CMD] $OSSL sdf -importrsakey -index $CLIENT_RSA_IDX -type enc -inkey $CLIENT_ENC_KEY"
    "$OSSL" sdf -importrsakey -index "$CLIENT_RSA_IDX" -type enc  -inkey "$CLIENT_ENC_KEY"  2>/dev/null
    echo ""
}

# build_client_opts: 条件拼接 -cert/-key/provider
build_client_opts() {
    local cert="$1" key="$2" prov="$3"
    local opts=""
    if [ -n "$cert" ]; then opts="$opts -cert $cert"; fi
    if [ -n "$key" ];  then opts="$opts -key $key"; fi
    if [ -n "$prov" ]; then opts="$opts $prov"; fi
    echo "$opts"
}

# run_handshake: port cipher
#   server_cert server_key server_prov
#   client_cert client_key client_prov [verify]
run_handshake() {
    local port="$1"
    local cipher="$2"
    local server_cert="$3"
    local server_key="$4"
    local server_prov="$5"
    local client_cert="$6"
    local client_key="$7"
    local client_prov="$8"
    local verify="${9:-}"
    local sf="$TMP/svr_${port}.txt"
    local cf="$TMP/cli_${port}.txt"

    local server_cmd="$OSSL s_server -accept $port $TLS_VERSION -cipher $cipher -cert $server_cert -key $server_key $server_prov -www"
    if [ -n "$verify" ]; then
        server_cmd="$server_cmd $verify"
    fi

    local client_opts
    client_opts=$(build_client_opts "$client_cert" "$client_key" "$client_prov")
    local client_cmd="$OSSL s_client -connect 127.0.0.1:$port $TLS_VERSION -cipher $cipher$client_opts"

    cleanup_port

    echo "    [CMD][server] $server_cmd"
    sh -c "$server_cmd" >"$sf" 2>&1 &
    local spid=$!
    sleep 3

    echo "    [CMD][client] printf 'Q' | $client_cmd"
    sh -c "printf 'Q\n' | $client_cmd" >"$cf" 2>&1 || true

    local i
    for i in $(seq 1 15); do
        sleep 1
        grep -q "Cipher is" "$cf" 2>/dev/null && break
    done

    if grep -q "Cipher is" "$cf" 2>/dev/null; then
        ok
        grep "Cipher is" "$cf" | sed 's/^/    /'
        grep "Protocol" "$cf" | sed 's/^/    /'
    else
        no
        grep -i "error" "$cf" 2>/dev/null | head -3 | sed 's/^/    Client: /'
        grep -i "error" "$sf" 2>/dev/null | head -3 | sed 's/^/    Server: /'
    fi

    kill "$spid" >/dev/null 2>&1 || true
    cleanup_port
}

echo "============================================================"
echo " TLS RSA Acceleration Test (with mTLS cross verification)"
echo " Server RSA2048 -> index $SERVER_RSA_IDX"
echo " Client RSA2048 -> index $CLIENT_RSA_IDX"
echo "============================================================"

# 导入密钥
import_keys

# ============================================================
# ECDHE-RSA 签名测试（单向认证）
# ============================================================
echo "==== ECDHE-RSA Sign Test (server auth) ===="

NUM=$((NUM + 1)); echo ""; echo "[$NUM] ECDHE-RSA HW server-sign (HW server, SW client)"
run_handshake $((PORT_BASE + 1)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "sdf:rsa:$SERVER_RSA_IDX:sign" "$PROV_SDF" \
    "" "" ""

NUM=$((NUM + 1)); echo ""; echo "[$NUM] ECDHE-RSA SW server-sign (baseline)"
run_handshake $((PORT_BASE + 2)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "$RSA_SIGN_KEY" "" \
    "" "" ""

# ============================================================
# TLS-RSA 解密测试（单向认证）
# ============================================================
echo ""
echo "==== TLS-RSA Decrypt Test (server auth) ===="

NUM=$((NUM + 1)); echo ""; echo "[$NUM] TLS-RSA HW server-decrypt (HW server, SW client)"
run_handshake $((PORT_BASE + 3)) "$RSA_CIPHER" \
    "$RSA_ENC_CERT" "sdf:rsa:$SERVER_RSA_IDX:enc" "$PROV_SDF" \
    "" "" ""

NUM=$((NUM + 1)); echo ""; echo "[$NUM] TLS-RSA SW server-decrypt (baseline)"
run_handshake $((PORT_BASE + 4)) "$RSA_CIPHER" \
    "$RSA_ENC_CERT" "$RSA_ENC_KEY" "" \
    "" "" ""

# ============================================================
# mTLS 双向认证测试（客户端也用 RSA 签名）
# ============================================================
echo ""
echo "==== mTLS ECDHE-RSA Cross Test (mutual auth) ===="

NUM=$((NUM + 1)); echo ""; echo "[$NUM] mTLS HW server + HW client (both HW sign)"
run_handshake $((PORT_BASE + 5)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "sdf:rsa:$SERVER_RSA_IDX:sign" "$PROV_SDF" \
    "$CLIENT_SIGN_CERT" "sdf:rsa:$CLIENT_RSA_IDX:sign" "$PROV_SDF" \
    "-Verify 2"

NUM=$((NUM + 1)); echo ""; echo "[$NUM] mTLS HW server + SW client"
run_handshake $((PORT_BASE + 6)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "sdf:rsa:$SERVER_RSA_IDX:sign" "$PROV_SDF" \
    "$CLIENT_SIGN_CERT" "$CLIENT_SIGN_KEY" "" \
    "-Verify 2"

NUM=$((NUM + 1)); echo ""; echo "[$NUM] mTLS SW server + HW client"
run_handshake $((PORT_BASE + 7)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "$RSA_SIGN_KEY" "" \
    "$CLIENT_SIGN_CERT" "sdf:rsa:$CLIENT_RSA_IDX:sign" "$PROV_SDF" \
    "-Verify 2"

NUM=$((NUM + 1)); echo ""; echo "[$NUM] mTLS SW server + SW client (baseline)"
run_handshake $((PORT_BASE + 8)) "$ECDHE_CIPHER" \
    "$RSA_SIGN_CERT" "$RSA_SIGN_KEY" "" \
    "$CLIENT_SIGN_CERT" "$CLIENT_SIGN_KEY" "" \
    "-Verify 2"

echo ""
echo "============================================================"
echo " SUMMARY: PASS=$PASS / $NUM, FAIL=$FAIL / $NUM"
echo "============================================================"

[ "$FAIL" -eq 0 ]
