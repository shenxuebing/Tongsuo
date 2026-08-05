#!/usr/bin/env bash
set -u

for arg in "$@"; do
    case "$arg" in
        *=*) export "$arg" ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

export OPENSSL_CONF="${OPENSSL_CONF:-$SCRIPT_DIR/openssl.cnf}"

if [ -x "$SCRIPT_DIR/openssl" ]; then
    OSSL="$SCRIPT_DIR/openssl"
elif [ -x "$SCRIPT_DIR/openssl.exe" ]; then
    OSSL="$SCRIPT_DIR/openssl.exe"
else
    echo "[FAIL] cannot find openssl in $SCRIPT_DIR"
    exit 1
fi

CERTS="${CERTS:-../test/certs}"

SM2_SERVER_IDX="${SM2_SERVER_IDX:-1}"
SM2_CLIENT_IDX="${SM2_CLIENT_IDX:-2}"
SM2_SERVER_SIGN_KEY="${SM2_SERVER_SIGN_KEY:-$CERTS/sm2/server_sign.key}"
SM2_SERVER_ENC_KEY="${SM2_SERVER_ENC_KEY:-$CERTS/sm2/server_enc.key}"
SM2_CLIENT_SIGN_KEY="${SM2_CLIENT_SIGN_KEY:-$CERTS/sm2/client_sign.key}"
SM2_CLIENT_ENC_KEY="${SM2_CLIENT_ENC_KEY:-$CERTS/sm2/client_enc.key}"

RSA1024_IDX="${RSA1024_IDX:-1}"
RSA2048_IDX="${RSA2048_IDX:-1}"
RSA3072_IDX="${RSA3072_IDX:-2}"
RSA4096_IDX="${RSA4096_IDX:-3}"

RSA1024_SIGN_KEY="${RSA1024_SIGN_KEY:-$CERTS/ee-key-1024.pem}"
RSA1024_ENC_KEY="${RSA1024_ENC_KEY:-$CERTS/ee-key-1024.pem}"
RSA2048_SIGN_KEY="${RSA2048_SIGN_KEY:-$CERTS/server-rsa-sign.key}"
RSA2048_ENC_KEY="${RSA2048_ENC_KEY:-$CERTS/server-rsa-enc.key}"
RSA3072_SIGN_KEY="${RSA3072_SIGN_KEY:-$CERTS/client_3072_sign.key}"
RSA3072_ENC_KEY="${RSA3072_ENC_KEY:-$CERTS/client_3072_enc.key}"
RSA4096_SIGN_KEY="${RSA4096_SIGN_KEY:-$CERTS/client_4096_sign.key}"
RSA4096_ENC_KEY="${RSA4096_ENC_KEY:-$CERTS/client_4096_enc.key}"

PASS=0
FAIL=0

ok() { echo "[OK]   $1"; PASS=$((PASS + 1)); }
no() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

check_file() {
    if [ ! -f "$1" ]; then
        no "missing key file: $1"
        return 1
    fi
    return 0
}

import_sm2() {
    label="$1"
    idx="$2"
    type="$3"
    key="$4"

    check_file "$key" || return 0
    echo "[INFO] $label: index=$idx type=$type key=$key"
    # 先删除可能已存在的密钥（忽略错误，索引可能为空）
    "$OSSL" sdf -delsm2key -index "$idx" -type "$type" 2>/dev/null
    if "$OSSL" sdf -importsm2key -index "$idx" -type "$type" -inkey "$key" 2>/dev/null; then
        ok "$label"
    else
        no "$label"
    fi
}

import_rsa() {
    label="$1"
    idx="$2"
    type="$3"
    key="$4"

    check_file "$key" || return 0
    echo "[INFO] $label: index=$idx type=$type key=$key"
    # RSA 复用 delsm2key 删除（厂商库底层按容器索引删除，与密钥类型无关）
    "$OSSL" sdf -delsm2key -index "$idx" -type "$type" 2>/dev/null
    if "$OSSL" sdf -importrsakey -index "$idx" -type "$type" -inkey "$key" 2>/dev/null; then
        ok "$label"
    else
        no "$label"
    fi
}

echo "============================================================"
echo " Import SDF keys"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo "============================================================"

import_sm2 "SM2 server sign" "$SM2_SERVER_IDX" "sign" "$SM2_SERVER_SIGN_KEY"
import_sm2 "SM2 server enc"  "$SM2_SERVER_IDX" "enc"  "$SM2_SERVER_ENC_KEY"
import_sm2 "SM2 client sign" "$SM2_CLIENT_IDX" "sign" "$SM2_CLIENT_SIGN_KEY"
import_sm2 "SM2 client enc"  "$SM2_CLIENT_IDX" "enc"  "$SM2_CLIENT_ENC_KEY"

import_rsa "RSA1024 sign" "$RSA1024_IDX" "sign" "$RSA1024_SIGN_KEY"
import_rsa "RSA1024 enc"  "$RSA1024_IDX" "enc"  "$RSA1024_ENC_KEY"
import_rsa "RSA2048 sign" "$RSA2048_IDX" "sign" "$RSA2048_SIGN_KEY"
import_rsa "RSA2048 enc"  "$RSA2048_IDX" "enc"  "$RSA2048_ENC_KEY"
import_rsa "RSA3072 sign" "$RSA3072_IDX" "sign" "$RSA3072_SIGN_KEY"
import_rsa "RSA3072 enc"  "$RSA3072_IDX" "enc"  "$RSA3072_ENC_KEY"
import_rsa "RSA4096 sign" "$RSA4096_IDX" "sign" "$RSA4096_SIGN_KEY"
import_rsa "RSA4096 enc"  "$RSA4096_IDX" "enc"  "$RSA4096_ENC_KEY"

echo
echo "============================================================"
echo " SUMMARY: PASS=$PASS FAIL=$FAIL"
echo "============================================================"

[ "$FAIL" -eq 0 ]
