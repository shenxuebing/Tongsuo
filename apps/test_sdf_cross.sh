#!/usr/bin/env bash
set -u

for arg in "$@"; do
    case "$arg" in
        *=*)
            export "$arg"
            ;;
    esac
done

export OPENSSL_CONF="${OPENSSL_CONF:-$(pwd)/openssl.cnf}"
export SDF_LIB_PATH="${SDF_LIB_PATH:-$(pwd)/libbyzk0018.so}"
export BYZK0018_SKIP_OPENSSL_PROVIDER_INIT="${BYZK0018_SKIP_OPENSSL_PROVIDER_INIT:-1}"
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

CERTS="../test/certs"
TMP="${TMP:-/tmp/sdf_cross}"
mkdir -p "$TMP"

PASS=0
FAIL=0
WARN=0

ok() { echo "  [OK]   $1"; PASS=$((PASS + 1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
wn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }
# 执行命令并检查结果，打印完整命令便于独立调试
q() {
    echo "        $*"
    if "$@" >/dev/null 2>/tmp/sdf_cross_err.txt; then
        return 0
    else
        echo "        --> FAILED, stderr:"
        tail -5 /tmp/sdf_cross_err.txt 2>/dev/null | sed 's/^/            /'
        return 1
    fi
}
qq() {
    "$@" >/dev/null 2>&1
}

SM2_SIGN_IDX="${SM2_SIGN_IDX:-1}"
SM2_ENC_IDX="${SM2_ENC_IDX:-1}"
SM2_SIGN_CERT="${SM2_SIGN_CERT:-$CERTS/sm2/server_sign.crt}"
SM2_SIGN_KEY="${SM2_SIGN_KEY:-$CERTS/sm2/server_sign.key}"
SM2_ENC_CERT="${SM2_ENC_CERT:-$CERTS/sm2/server_enc.crt}"
SM2_ENC_KEY="${SM2_ENC_KEY:-$CERTS/sm2/server_enc.key}"
SM2_CAFILE="${SM2_CAFILE:-$CERTS/sm2/chain-ca.crt}"

RSA2048_SIGN_IDX="${RSA2048_SIGN_IDX:-${RSA2048_IDX:-1}}"
RSA2048_ENC_IDX="${RSA2048_ENC_IDX:-${RSA2048_IDX:-1}}"
RSA3072_SIGN_IDX="${RSA3072_SIGN_IDX:-${RSA3072_IDX:-2}}"
RSA3072_ENC_IDX="${RSA3072_ENC_IDX:-${RSA3072_IDX:-2}}"
RSA4096_SIGN_IDX="${RSA4096_SIGN_IDX:-${RSA4096_IDX:-3}}"
RSA4096_ENC_IDX="${RSA4096_ENC_IDX:-${RSA4096_IDX:-3}}"

RSA2048_SIGN_CERT="${RSA2048_SIGN_CERT:-$CERTS/server-rsa-sign.crt}"
RSA2048_SIGN_KEY="${RSA2048_SIGN_KEY:-$CERTS/server-rsa-sign.key}"
RSA2048_ENC_CERT="${RSA2048_ENC_CERT:-$CERTS/server-rsa-enc.crt}"
RSA2048_ENC_KEY="${RSA2048_ENC_KEY:-$CERTS/server-rsa-enc.key}"

RSA3072_SIGN_CERT="${RSA3072_SIGN_CERT:-$CERTS/client_3072_sign.crt}"
RSA3072_SIGN_KEY="${RSA3072_SIGN_KEY:-$CERTS/client_3072_sign.key}"
RSA3072_ENC_CERT="${RSA3072_ENC_CERT:-$CERTS/client_3072_enc.crt}"
RSA3072_ENC_KEY="${RSA3072_ENC_KEY:-$CERTS/client_3072_enc.key}"

RSA4096_SIGN_CERT="${RSA4096_SIGN_CERT:-$CERTS/client_4096_sign.crt}"
RSA4096_SIGN_KEY="${RSA4096_SIGN_KEY:-$CERTS/client_4096_sign.key}"
RSA4096_ENC_CERT="${RSA4096_ENC_CERT:-$CERTS/client_4096_enc.crt}"
RSA4096_ENC_KEY="${RSA4096_ENC_KEY:-$CERTS/client_4096_enc.key}"

copy_local() {
    src="$1"
    dst="$2"
    [ -f "$src" ] || return 1
    cp -f "$src" "$dst"
}

extract_pub_from_cert() {
    cert="$1"
    out="$2"
    q "$OSSL" x509 -provider default -in "$cert" -pubkey -noout > "$out"
}

run_sm2_suite() {
    sign_idx="$1"
    enc_idx="$2"
    sign_cert="$3"
    sign_key="$4"
    enc_cert="$5"
    enc_key="$6"
    cafile="$7"

    sign_local="$TMP/sm2_sign.crt"
    enc_local="$TMP/sm2_enc.crt"
    sign_pub="$TMP/sm2_sign_pub.pem"
    enc_pub="$TMP/sm2_enc_pub.pem"

    echo ""
    echo "==== SM2 suite (sign_idx=$sign_idx enc_idx=$enc_idx) ===="

    if ! copy_local "$sign_cert" "$sign_local"; then
        no "SM2 missing sign cert: $sign_cert"
        return 0
    fi
    if ! copy_local "$enc_cert" "$enc_local"; then
        no "SM2 missing enc cert: $enc_cert"
        return 0
    fi
    if ! extract_pub_from_cert "$sign_local" "$sign_pub"; then
        no "SM2 extract sign pub"
        return 0
    fi
    if ! extract_pub_from_cert "$enc_local" "$enc_pub"; then
        no "SM2 extract enc pub"
        return 0
    fi

    if q "$OSSL" dgst -sm3 -provider sdfprov -provider default \
        -sign "sdf:sm2:${sign_idx}:sign" -out "$TMP/sm2_p1_h.bin" "$TMP/plain.txt"; then
        if q "$OSSL" dgst -sm3 -provider default \
            -verify "$sign_pub" -signature "$TMP/sm2_p1_h.bin" "$TMP/plain.txt" | grep -q "Verified OK"; then
            ok "SM2 P1 HW-sign -> SW-verify"
        else
            wn "SM2 P1 HW-sign -> SW-verify (certificate/key mismatch?)"
        fi
    else
        no "SM2 P1 HW-sign"
    fi

    if q "$OSSL" dgst -sm3 -provider default \
        -sign "$sign_key" -out "$TMP/sm2_p1_s.bin" "$TMP/plain.txt"; then
        if q "$OSSL" dgst -sm3 -provider default \
            -verify "$sign_pub" -signature "$TMP/sm2_p1_s.bin" "$TMP/plain.txt" | grep -q "Verified OK"; then
            ok "SM2 P1 SW-sign -> SW-verify (baseline)"
        else
            no "SM2 P1 SW-sign -> SW-verify (baseline)"
        fi
    else
        no "SM2 P1 baseline sign"
    fi

    if q "$OSSL" pkeyutl -provider default -encrypt -pubin -inkey "$enc_pub" \
        -in "$TMP/plain.txt" -out "$TMP/sm2_ct.bin"; then
        if q "$OSSL" pkeyutl -provider sdfprov -provider default -decrypt \
            -inkey "sdf:sm2:${enc_idx}:enc" -in "$TMP/sm2_ct.bin" -out "$TMP/sm2_pt.txt"; then
            if cmp -s "$TMP/plain.txt" "$TMP/sm2_pt.txt"; then
                ok "SM2 plain SW-encrypt -> HW-decrypt"
            else
                wn "SM2 plain SW-encrypt -> HW-decrypt (cert/index mismatch?)"
            fi
        else
            no "SM2 plain HW-decrypt"
        fi
    else
        no "SM2 plain SW-encrypt"
    fi

    if q "$OSSL" pkeyutl -provider default -decrypt -inkey "$enc_key" \
        -in "$TMP/sm2_ct.bin" -out "$TMP/sm2_pt2.txt"; then
        if cmp -s "$TMP/plain.txt" "$TMP/sm2_pt2.txt"; then
            ok "SM2 plain SW-encrypt -> SW-decrypt (baseline)"
        else
            no "SM2 plain SW baseline content mismatch"
        fi
    else
        no "SM2 plain SW baseline decrypt"
    fi

    if q "$OSSL" pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached \
        -in "$TMP/plain.txt" -out "$TMP/sm2_p7_h.p7" -outform DER \
        -signer "$sign_local" -inkey "sdf:sm2:${sign_idx}:sign"; then
        if qq "$OSSL" pkcs7 -verify -provider default \
            -in "$TMP/sm2_p7_h.p7" -inform DER -content "$TMP/plain.txt" -CAfile "$cafile"; then
            ok "SM2 P7 HW-sign -> SW-verify"
        else
            wn "SM2 P7 HW-sign -> SW-verify (certificate/key mismatch?)"
        fi
    else
        no "SM2 P7 HW-sign"
    fi

    if q "$OSSL" pkcs7 -sign -gmt0010 -provider default -detached \
        -in "$TMP/plain.txt" -out "$TMP/sm2_p7_s.p7" -outform DER \
        -signer "$sign_local" -inkey "$sign_key"; then
        if qq "$OSSL" pkcs7 -verify -provider default \
            -in "$TMP/sm2_p7_s.p7" -inform DER -content "$TMP/plain.txt" -CAfile "$cafile"; then
            ok "SM2 P7 SW-sign -> SW-verify (baseline)"
        else
            no "SM2 P7 SW-sign -> SW-verify (baseline)"
        fi
    else
        no "SM2 P7 baseline sign"
    fi

    if q "$OSSL" pkcs7 -encrypt -gmt0010 -provider sdfprov -provider default \
        -in "$TMP/plain.txt" -out "$TMP/sm2_env_h.p7" -outform DER "$enc_local"; then
        if q "$OSSL" pkcs7 -decrypt -provider sdfprov -provider default \
            -in "$TMP/sm2_env_h.p7" -inform DER -out "$TMP/sm2_env_dec.txt" \
            -inkey "sdf:sm2:${enc_idx}:enc" -recip "$enc_local"; then
            if cmp -s "$TMP/plain.txt" "$TMP/sm2_env_dec.txt"; then
                ok "SM2 envelope SW-encrypt -> HW-decrypt"
            else
                wn "SM2 envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)"
            fi
        else
            no "SM2 envelope HW-decrypt"
        fi
    else
        no "SM2 envelope SW-encrypt"
    fi

    if q "$OSSL" pkcs7 -decrypt -provider default \
        -in "$TMP/sm2_env_h.p7" -inform DER -out "$TMP/sm2_env_dec2.txt" \
        -inkey "$enc_key" -recip "$enc_local"; then
        if cmp -s "$TMP/plain.txt" "$TMP/sm2_env_dec2.txt"; then
            ok "SM2 envelope SW-encrypt -> SW-decrypt (baseline)"
        else
            no "SM2 envelope SW baseline content mismatch"
        fi
    else
        no "SM2 envelope SW baseline decrypt"
    fi
}

run_rsa_suite() {
    label="$1"
    sign_idx="$2"
    enc_idx="$3"
    sign_cert="$4"
    sign_key="$5"
    enc_cert="$6"
    enc_key="$7"
    tag="$8"

    sign_local="$TMP/${tag}_sign.crt"
    enc_local="$TMP/${tag}_enc.crt"
    sign_pub="$TMP/${tag}_sign_pub.pem"
    plain_ct="$TMP/${tag}_plain.ct"
    plain_pt="$TMP/${tag}_plain.pt"
    p1_sig="$TMP/${tag}_p1.sig"
    p7_sig="$TMP/${tag}_p7.der"
    env_der="$TMP/${tag}_env.der"
    env_pt="$TMP/${tag}_env.pt"

    echo ""
    echo "==== $label suite (sign_idx=$sign_idx enc_idx=$enc_idx) ===="

    if [ -z "$sign_idx" ] || [ -z "$enc_idx" ]; then
        wn "$label skipped (set ${label}_SIGN_IDX / ${label}_ENC_IDX or shared override)"
        return 0
    fi
    if ! copy_local "$sign_cert" "$sign_local"; then
        wn "$label skipped (missing sign cert: $sign_cert)"
        return 0
    fi
    if ! copy_local "$enc_cert" "$enc_local"; then
        wn "$label skipped (missing enc cert: $enc_cert)"
        return 0
    fi
    if ! extract_pub_from_cert "$sign_local" "$sign_pub"; then
        no "$label extract sign pub"
        return 0
    fi

    if q "$OSSL" dgst -sha256 -provider sdfprov -provider default \
        -sign "sdf:rsa:${sign_idx}:sign" -out "$p1_sig" "$TMP/plain.txt"; then
        if q "$OSSL" dgst -sha256 -provider default \
            -verify "$sign_pub" -signature "$p1_sig" "$TMP/plain.txt" | grep -q "Verified OK"; then
            ok "$label P1 HW-sign -> SW-verify"
        else
            wn "$label P1 HW-sign -> SW-verify (certificate/key mismatch?)"
        fi
    else
        no "$label P1 HW-sign"
    fi

    if q "$OSSL" dgst -sha256 -provider default \
        -sign "$sign_key" -out "$TMP/${tag}_p1_sw.sig" "$TMP/plain.txt"; then
        if q "$OSSL" dgst -sha256 -provider default \
            -verify "$sign_pub" -signature "$TMP/${tag}_p1_sw.sig" "$TMP/plain.txt" | grep -q "Verified OK"; then
            ok "$label P1 SW-sign -> SW-verify (baseline)"
        else
            no "$label P1 SW-sign -> SW-verify (baseline)"
        fi
    else
        no "$label P1 baseline sign"
    fi

    if q "$OSSL" pkeyutl -provider default -encrypt -certin -inkey "$enc_local" \
        -in "$TMP/plain.txt" -out "$plain_ct"; then
        if q "$OSSL" pkeyutl -provider sdfprov -provider default -decrypt \
            -inkey "sdf:rsa:${enc_idx}:enc" -in "$plain_ct" -out "$plain_pt"; then
            if cmp -s "$TMP/plain.txt" "$plain_pt"; then
                ok "$label plain SW-encrypt -> HW-decrypt"
            else
                wn "$label plain SW-encrypt -> HW-decrypt (cert/index mismatch?)"
            fi
        else
            wn "$label plain HW-decrypt (device key missing or mismatch?)"
        fi
    else
        no "$label plain SW-encrypt"
    fi

    if q "$OSSL" pkeyutl -provider default -decrypt -inkey "$enc_key" \
        -in "$plain_ct" -out "$TMP/${tag}_plain_sw.pt"; then
        if cmp -s "$TMP/plain.txt" "$TMP/${tag}_plain_sw.pt"; then
            ok "$label plain SW-encrypt -> SW-decrypt (baseline)"
        else
            no "$label plain SW baseline content mismatch"
        fi
    else
        no "$label plain SW baseline decrypt"
    fi

    if q "$OSSL" pkcs7 -sign -provider sdfprov -provider default -detached \
        -in "$TMP/plain.txt" -out "$p7_sig" -outform DER \
        -signer "$sign_local" -inkey "sdf:rsa:${sign_idx}:sign"; then
        if qq "$OSSL" pkcs7 -verify -provider default \
            -in "$p7_sig" -inform DER -content "$TMP/plain.txt" -noverify; then
            ok "$label P7 HW-sign -> SW-verify"
        else
            wn "$label P7 HW-sign -> SW-verify (certificate/key mismatch?)"
        fi
    else
        wn "$label P7 HW-sign (device sign cert mismatch?)"
    fi

    if q "$OSSL" pkcs7 -sign -provider default -detached \
        -in "$TMP/plain.txt" -out "$TMP/${tag}_p7_sw.der" -outform DER \
        -signer "$sign_local" -inkey "$sign_key"; then
        if qq "$OSSL" pkcs7 -verify -provider default \
            -in "$TMP/${tag}_p7_sw.der" -inform DER -content "$TMP/plain.txt" -noverify; then
            ok "$label P7 SW-sign -> SW-verify (baseline)"
        else
            no "$label P7 SW-sign -> SW-verify (baseline)"
        fi
    else
        no "$label P7 baseline sign"
    fi

    if q "$OSSL" smime -encrypt -binary -outform DER -in "$TMP/plain.txt" \
        -out "$env_der" "$enc_local"; then
        if q "$OSSL" smime -decrypt -inform DER -in "$env_der" \
            -recip "$enc_local" -inkey "sdf:rsa:${enc_idx}:enc" \
            -provider sdfprov -provider default -out "$env_pt"; then
            if cmp -s "$TMP/plain.txt" "$env_pt"; then
                ok "$label envelope SW-encrypt -> HW-decrypt"
            else
                wn "$label envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)"
            fi
        else
            wn "$label envelope HW-decrypt (device enc key missing or mismatch?)"
        fi
    else
        no "$label envelope SW-encrypt"
    fi

    if q "$OSSL" smime -decrypt -inform DER -in "$env_der" \
        -recip "$enc_local" -inkey "$enc_key" -provider default \
        -out "$TMP/${tag}_env_sw.pt"; then
        if cmp -s "$TMP/plain.txt" "$TMP/${tag}_env_sw.pt"; then
            ok "$label envelope SW-encrypt -> SW-decrypt (baseline)"
        else
            no "$label envelope SW baseline content mismatch"
        fi
    else
        no "$label envelope SW baseline decrypt"
    fi
}

echo "============================================================"
echo " SDF Provider Cross Verification"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo "============================================================"

printf "cross verify payload 0123456789" > "$TMP/plain.txt"

run_sm2_suite "$SM2_SIGN_IDX" "$SM2_ENC_IDX" \
    "$SM2_SIGN_CERT" "$SM2_SIGN_KEY" "$SM2_ENC_CERT" "$SM2_ENC_KEY" "$SM2_CAFILE"

run_rsa_suite "RSA2048" "$RSA2048_SIGN_IDX" "$RSA2048_ENC_IDX" \
    "$RSA2048_SIGN_CERT" "$RSA2048_SIGN_KEY" "$RSA2048_ENC_CERT" "$RSA2048_ENC_KEY" "rsa2048"

run_rsa_suite "RSA3072" "$RSA3072_SIGN_IDX" "$RSA3072_ENC_IDX" \
    "$RSA3072_SIGN_CERT" "$RSA3072_SIGN_KEY" "$RSA3072_ENC_CERT" "$RSA3072_ENC_KEY" "rsa3072"

run_rsa_suite "RSA4096" "$RSA4096_SIGN_IDX" "$RSA4096_ENC_IDX" \
    "$RSA4096_SIGN_CERT" "$RSA4096_SIGN_KEY" "$RSA4096_ENC_CERT" "$RSA4096_ENC_KEY" "rsa4096"

echo ""
echo "============================================================"
echo " SUMMARY:  PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
echo " (WARN = device key missing, cert/index mismatch, or optional suite not enabled)"
echo "============================================================"

[ "$FAIL" -eq 0 ]
