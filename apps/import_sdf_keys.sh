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

OSSL="${OSSL:-openssl}"

CERTS="${CERTS:-./certs}"
SM2_CERTS="${SM2_CERTS:-$CERTS/sm2}"
RSA_CERTS="${RSA_CERTS:-$CERTS/rsa}"

SM2_SERVER_IDX="${SM2_SERVER_IDX:-1}"
SM2_CLIENT_IDX="${SM2_CLIENT_IDX:-2}"
SM2_SERVER_SIGN_KEY="${SM2_SERVER_SIGN_KEY:-$SM2_CERTS/sm2_server_sign.key}"
SM2_SERVER_ENC_KEY="${SM2_SERVER_ENC_KEY:-$SM2_CERTS/sm2_server_enc.key}"
SM2_CLIENT_SIGN_KEY="${SM2_CLIENT_SIGN_KEY:-$SM2_CERTS/sm2_client_sign.key}"
SM2_CLIENT_ENC_KEY="${SM2_CLIENT_ENC_KEY:-$SM2_CERTS/sm2_client_enc.key}"

RSA1024_IDX="${RSA1024_IDX:-1}"
RSA2048_IDX="${RSA2048_IDX:-2}"
RSA3072_IDX="${RSA3072_IDX:-3}"
RSA4096_IDX="${RSA4096_IDX:-4}"

RSA1024_SIGN_KEY="${RSA1024_SIGN_KEY:-$RSA_CERTS/rsa1024_sign.key}"
RSA1024_ENC_KEY="${RSA1024_ENC_KEY:-$RSA_CERTS/rsa1024_enc.key}"
RSA2048_SIGN_KEY="${RSA2048_SIGN_KEY:-$RSA_CERTS/rsa2048_sign.key}"
RSA2048_ENC_KEY="${RSA2048_ENC_KEY:-$RSA_CERTS/rsa2048_enc.key}"
RSA3072_SIGN_KEY="${RSA3072_SIGN_KEY:-$RSA_CERTS/rsa3072_sign.key}"
RSA3072_ENC_KEY="${RSA3072_ENC_KEY:-$RSA_CERTS/rsa3072_enc.key}"
RSA4096_SIGN_KEY="${RSA4096_SIGN_KEY:-$RSA_CERTS/rsa4096_sign.key}"
RSA4096_ENC_KEY="${RSA4096_ENC_KEY:-$RSA_CERTS/rsa4096_enc.key}"
IMPORT_GROUP="${IMPORT_GROUP:-all}"

DO_SM2=0
DO_RSA=0
case "$IMPORT_GROUP" in
    all)
        DO_SM2=1
        DO_RSA=1
        ;;
    sm2)
        DO_SM2=1
        ;;
    rsa)
        DO_RSA=1
        ;;
    *)
        echo "[FAIL] unknown IMPORT_GROUP=$IMPORT_GROUP (expected all, sm2, or rsa)"
        exit 1
        ;;
esac

PASS=0
FAIL=0

ok() { echo "[OK]   $1"; PASS=$((PASS + 1)); }
no() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

run() {
    printf '[CMD] ' >&2
    printf '%q ' "$@" >&2
    printf '\n' >&2
    "$@"
}

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
    run "$OSSL" sdf -delsm2key -index "$idx" -type "$type"
    if run "$OSSL" sdf -importsm2key -index "$idx" -type "$type" -inkey "$key"; then
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
    # Delete existing RSA key first. Ignore errors because the index may be empty.
    run "$OSSL" sdf -delrsakey -index "$idx" -type "$type"
    if run "$OSSL" sdf -importrsakey -index "$idx" -type "$type" -inkey "$key"; then
        ok "$label"
    else
        no "$label"
    fi
}

echo "============================================================"
echo " Import SDF keys"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo " IMPORT_GROUP=$IMPORT_GROUP"
echo "============================================================"

if [ "$DO_SM2" -eq 1 ]; then
    import_sm2 "SM2 server sign" "$SM2_SERVER_IDX" "sign" "$SM2_SERVER_SIGN_KEY"
    import_sm2 "SM2 server enc"  "$SM2_SERVER_IDX" "enc"  "$SM2_SERVER_ENC_KEY"
    import_sm2 "SM2 client sign" "$SM2_CLIENT_IDX" "sign" "$SM2_CLIENT_SIGN_KEY"
    import_sm2 "SM2 client enc"  "$SM2_CLIENT_IDX" "enc"  "$SM2_CLIENT_ENC_KEY"
fi

if [ "$DO_RSA" -eq 1 ]; then
    import_rsa "RSA1024 sign" "$RSA1024_IDX" "sign" "$RSA1024_SIGN_KEY"
    import_rsa "RSA1024 enc"  "$RSA1024_IDX" "enc"  "$RSA1024_ENC_KEY"
    import_rsa "RSA2048 sign" "$RSA2048_IDX" "sign" "$RSA2048_SIGN_KEY"
    import_rsa "RSA2048 enc"  "$RSA2048_IDX" "enc"  "$RSA2048_ENC_KEY"
    import_rsa "RSA3072 sign" "$RSA3072_IDX" "sign" "$RSA3072_SIGN_KEY"
    import_rsa "RSA3072 enc"  "$RSA3072_IDX" "enc"  "$RSA3072_ENC_KEY"
    import_rsa "RSA4096 sign" "$RSA4096_IDX" "sign" "$RSA4096_SIGN_KEY"
    import_rsa "RSA4096 enc"  "$RSA4096_IDX" "enc"  "$RSA4096_ENC_KEY"
fi

echo
echo "============================================================"
echo " SUMMARY: PASS=$PASS FAIL=$FAIL"
echo "============================================================"

[ "$FAIL" -eq 0 ]
