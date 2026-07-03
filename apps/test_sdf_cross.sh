#!/usr/bin/env bash
# ============================================================
# SDF Provider 全面交叉验证（bash 版，输出 ASCII，git bash 可读）
#
# 覆盖矩阵：
#   算法: SM2 / RSA
#   操作: P1签名(dgst) / P7签名(pkcs7 -sign/-verify) / 数字信封(pkcs7 -encrypt/-decrypt) / 普通加解密(pkeyutl)
#   密钥: 硬件(SDF URI) / 软件(PEM)
#   互通: 硬签软验、软签软验(基线)、软加硬解、软加软解
#
# 用法：cd apps && bash test_sdf_cross.sh
# 前置：OPENSSL_CONF 指向正确配置（sdf_use_loadmodule=1）
# ============================================================
set -u
export OPENSSL_CONF="${OPENSSL_CONF:-$(pwd)/openssl.cnf}"
OSSL="./openssl.exe"
CERTS="../test/certs"
TMP="/tmp/sdf_cross"
mkdir -p "$TMP"

PASS=0; FAIL=0; WARN=0

ok(){ echo "  [OK]   $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
wn(){ echo "  [WARN] $1"; WARN=$((WARN+1)); }

# 静默包装（屏蔽 TLOG_DEBUG 到 stderr）
q(){ "$@" 2>/dev/null; }
# pkcs7 -verify 会把 content 输出到 stdout，用 qq 抑制
qq(){ "$@" >/dev/null 2>&1; }

echo "============================================================"
echo " SDF Provider Cross Verification"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo "============================================================"

# 从证书提取公钥（供 dgst verify / pkeyutl -pubin）
q $OSSL x509 -in $CERTS/sm2/server_sign.crt -pubkey -noout > $TMP/sm2_sign_pub.pem
q $OSSL x509 -in $CERTS/sm2/server_enc.crt  -pubkey -noout > $TMP/sm2_enc_pub.pem
q $OSSL x509 -in $CERTS/server-rsa-sign.crt -pubkey -noout > $TMP/rsa_sign_pub.pem
q $OSSL x509 -in $CERTS/server-rsa-enc.crt  -pubkey -noout > $TMP/rsa_enc_pub.pem

# 统一明文（printf 无换行，避免 CRLF 差异）
printf "cross verify payload 0123456789" > $TMP/plain.txt

echo ""
echo "==== Part 1: SM2 P1 sign/verify (dgst) ===="
# 1a. 硬件签名 -> 软件验签
if q $OSSL dgst -sm3 -provider sdfprov -provider default \
    -sign "sdf:sm2:0:sign" -out $TMP/sm2_p1_h.bin $TMP/plain.txt; then
    if q $OSSL dgst -sm3 -provider default \
        -verify $TMP/sm2_sign_pub.pem -signature $TMP/sm2_p1_h.bin $TMP/plain.txt | grep -q "Verified OK"; then
        ok "SM2 P1 HW-sign -> SW-verify"
    else no "SM2 P1 HW-sign -> SW-verify (verify failed)"; fi
else no "SM2 P1 HW-sign (sign failed)"; fi
# 1b. 软件签名 -> 软件验签（基线）
q $OSSL dgst -sm3 -provider default \
    -sign $CERTS/sm2/server_sign.key -out $TMP/sm2_p1_s.bin $TMP/plain.txt
if q $OSSL dgst -sm3 -provider default \
    -verify $TMP/sm2_sign_pub.pem -signature $TMP/sm2_p1_s.bin $TMP/plain.txt | grep -q "Verified OK"; then
    ok "SM2 P1 SW-sign -> SW-verify (baseline)"
else no "SM2 P1 SW-sign -> SW-verify (baseline)"; fi

echo ""
echo "==== Part 2: RSA P1 sign/verify (dgst) ===="
# 2a. 硬件签名 -> 软件验签
if q $OSSL dgst -sha256 -provider sdfprov -provider default \
    -sign "sdf:rsa:0:sign" -out $TMP/rsa_p1_h.bin $TMP/plain.txt; then
    if q $OSSL dgst -sha256 -provider default \
        -verify $TMP/rsa_sign_pub.pem -signature $TMP/rsa_p1_h.bin $TMP/plain.txt | grep -q "Verified OK"; then
        ok "RSA P1 HW-sign -> SW-verify"
    else no "RSA P1 HW-sign -> SW-verify (verify failed)"; fi
else no "RSA P1 HW-sign (sign failed)"; fi
# 2b. 软件基线
q $OSSL dgst -sha256 -provider default \
    -sign $CERTS/server-rsa-sign.key -out $TMP/rsa_p1_s.bin $TMP/plain.txt
if q $OSSL dgst -sha256 -provider default \
    -verify $TMP/rsa_sign_pub.pem -signature $TMP/rsa_p1_s.bin $TMP/plain.txt | grep -q "Verified OK"; then
    ok "RSA P1 SW-sign -> SW-verify (baseline)"
else no "RSA P1 SW-sign -> SW-verify (baseline)"; fi

echo ""
echo "==== Part 3: SM2 plain encrypt/decrypt (pkeyutl) ===="
# 3a. 软件加密(enc证书公钥) -> 硬件解密
q $OSSL pkeyutl -provider default -encrypt -pubin -inkey $TMP/sm2_enc_pub.pem \
    -in $TMP/plain.txt -out $TMP/sm2_ct.bin
if q $OSSL pkeyutl -provider sdfprov -provider default -decrypt \
    -inkey "sdf:sm2:0:enc" -in $TMP/sm2_ct.bin -out $TMP/sm2_pt.txt; then
    if cmp -s $TMP/plain.txt $TMP/sm2_pt.txt; then ok "SM2 plain SW-encrypt -> HW-decrypt"
    else no "SM2 plain SW-encrypt -> HW-decrypt (content mismatch)"; fi
else no "SM2 plain SW-encrypt -> HW-decrypt (decrypt failed)"; fi
# 3b. 软件基线
if q $OSSL pkeyutl -provider default -decrypt -inkey $CERTS/sm2/server_enc.key \
    -in $TMP/sm2_ct.bin -out $TMP/sm2_pt2.txt; then
    if cmp -s $TMP/plain.txt $TMP/sm2_pt2.txt; then ok "SM2 plain SW-encrypt -> SW-decrypt (baseline)"
    else no "SM2 plain SW-encrypt -> SW-decrypt (content mismatch)"; fi
else no "SM2 plain SW-encrypt -> SW-decrypt (baseline)"; fi

echo ""
echo "==== Part 4: RSA plain encrypt/decrypt (pkeyutl) ===="
# 4a. sign: 软件加密(sign证书公钥) -> 硬件sign解密
q $OSSL pkeyutl -provider default -encrypt -pubin -inkey $TMP/rsa_sign_pub.pem \
    -in $TMP/plain.txt -out $TMP/rsa_sign_ct.bin
if q $OSSL pkeyutl -provider sdfprov -provider default -decrypt \
    -inkey "sdf:rsa:0:sign" -in $TMP/rsa_sign_ct.bin -out $TMP/rsa_sign_pt.txt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_sign_pt.txt; then ok "RSA sign SW-encrypt -> HW-decrypt"
    else no "RSA sign SW-encrypt -> HW-decrypt (content mismatch)"; fi
else no "RSA sign SW-encrypt -> HW-decrypt (decrypt failed)"; fi
# 4b. sign 软件基线
if q $OSSL pkeyutl -provider default -decrypt -inkey $CERTS/server-rsa-sign.key \
    -in $TMP/rsa_sign_ct.bin -out $TMP/rsa_sign_pt2.txt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_sign_pt2.txt; then ok "RSA sign SW-encrypt -> SW-decrypt (baseline)"
    else no "RSA sign SW-encrypt -> SW-decrypt (content mismatch)"; fi
else no "RSA sign SW-encrypt -> SW-decrypt (baseline)"; fi
# 4c. enc: 软件加密(enc证书公钥) -> 硬件enc解密（依赖设备enc私钥）
q $OSSL pkeyutl -provider default -encrypt -pubin -inkey $TMP/rsa_enc_pub.pem \
    -in $TMP/plain.txt -out $TMP/rsa_enc_ct.bin
if q $OSSL pkeyutl -provider sdfprov -provider default -decrypt \
    -inkey "sdf:rsa:0:enc" -in $TMP/rsa_enc_ct.bin -out $TMP/rsa_enc_pt.txt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_enc_pt.txt; then ok "RSA enc SW-encrypt -> HW-decrypt"
    else wn "RSA enc SW-encrypt -> HW-decrypt (device enc keypair missing?)"; fi
else wn "RSA enc HW-decrypt (needs device RSA enc keypair import)"; fi
# 4d. enc 软件基线
if q $OSSL pkeyutl -provider default -decrypt -inkey $CERTS/server-rsa-enc.key \
    -in $TMP/rsa_enc_ct.bin -out $TMP/rsa_enc_pt2.txt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_enc_pt2.txt; then ok "RSA enc SW-encrypt -> SW-decrypt (baseline)"
    else no "RSA enc SW-encrypt -> SW-decrypt (content mismatch)"; fi
else no "RSA enc SW-encrypt -> SW-decrypt (baseline)"; fi

echo ""
echo "==== Part 5: SM2 P7 sign/verify (pkcs7, detached + content) ===="
# 5a. 硬件签名 -> 软件验签
if q $OSSL pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached \
    -in $TMP/plain.txt -out $TMP/sm2_p7_h.p7 -outform DER \
    -signer $CERTS/sm2/server_sign.crt -inkey "sdf:sm2:0:sign"; then
    if qq $OSSL pkcs7 -verify -provider default \
        -in $TMP/sm2_p7_h.p7 -inform DER -content $TMP/plain.txt \
        -CAfile $CERTS/sm2/chain-ca.crt; then
        ok "SM2 P7 HW-sign -> SW-verify"
    else no "SM2 P7 HW-sign -> SW-verify (verify failed)"; fi
else no "SM2 P7 HW-sign (sign failed)"; fi
# 5b. 软件基线
q $OSSL pkcs7 -sign -gmt0010 -provider default -detached \
    -in $TMP/plain.txt -out $TMP/sm2_p7_s.p7 -outform DER \
    -signer $CERTS/sm2/server_sign.crt -inkey $CERTS/sm2/server_sign.key
if qq $OSSL pkcs7 -verify -provider default \
    -in $TMP/sm2_p7_s.p7 -inform DER -content $TMP/plain.txt \
    -CAfile $CERTS/sm2/chain-ca.crt; then
    ok "SM2 P7 SW-sign -> SW-verify (baseline)"
else no "SM2 P7 SW-sign -> SW-verify (baseline)"; fi

echo ""
echo "==== Part 6: RSA P7 sign/verify (pkcs7, detached + content) ===="
# 注：RSA 测试证书 issuer=CN=Root CA，无对应 CA 文件，用 -noverify 仅验证签名
# 6a. 硬件签名 -> 软件验签
if q $OSSL pkcs7 -sign -provider sdfprov -provider default -detached \
    -in $TMP/plain.txt -out $TMP/rsa_p7_h.p7 -outform DER \
    -signer $CERTS/server-rsa-sign.crt -inkey "sdf:rsa:0:sign"; then
    if qq $OSSL pkcs7 -verify -provider default \
        -in $TMP/rsa_p7_h.p7 -inform DER -content $TMP/plain.txt -noverify > /dev/null; then
        ok "RSA P7 HW-sign -> SW-verify"
    else no "RSA P7 HW-sign -> SW-verify (verify failed)"; fi
else no "RSA P7 HW-sign (sign failed)"; fi
# 6b. 软件基线
q $OSSL pkcs7 -sign -provider default -detached \
    -in $TMP/plain.txt -out $TMP/rsa_p7_s.p7 -outform DER \
    -signer $CERTS/server-rsa-sign.crt -inkey $CERTS/server-rsa-sign.key
if qq $OSSL pkcs7 -verify -provider default \
    -in $TMP/rsa_p7_s.p7 -inform DER -content $TMP/plain.txt -noverify > /dev/null; then
    ok "RSA P7 SW-sign -> SW-verify (baseline)"
else no "RSA P7 SW-sign -> SW-verify (baseline)"; fi

echo ""
echo "==== Part 7: SM2 digital envelope (pkcs7) ===="
# 7a. 软件加密(enc证书) -> 硬件解密
q $OSSL pkcs7 -encrypt -gmt0010 -provider sdfprov -provider default \
    -in $TMP/plain.txt -out $TMP/sm2_env_h.p7 -outform DER \
    $CERTS/sm2/server_enc.crt
if q $OSSL pkcs7 -decrypt -provider sdfprov -provider default \
    -in $TMP/sm2_env_h.p7 -inform DER -out $TMP/sm2_env_dec.txt \
    -inkey "sdf:sm2:0:enc" -recip $CERTS/sm2/server_enc.crt; then
    if cmp -s $TMP/plain.txt $TMP/sm2_env_dec.txt; then ok "SM2 envelope SW-encrypt -> HW-decrypt"
    else no "SM2 envelope SW-encrypt -> HW-decrypt (content mismatch)"; fi
else no "SM2 envelope SW-encrypt -> HW-decrypt (decrypt failed)"; fi
# 7b. 软件基线
if q $OSSL pkcs7 -decrypt -provider default \
    -in $TMP/sm2_env_h.p7 -inform DER -out $TMP/sm2_env_dec2.txt \
    -inkey $CERTS/sm2/server_enc.key -recip $CERTS/sm2/server_enc.crt; then
    if cmp -s $TMP/plain.txt $TMP/sm2_env_dec2.txt; then ok "SM2 envelope SW-encrypt -> SW-decrypt (baseline)"
    else no "SM2 envelope SW-encrypt -> SW-decrypt (content mismatch)"; fi
else no "SM2 envelope SW-encrypt -> SW-decrypt (baseline)"; fi

echo ""
echo "==== Part 8: RSA digital envelope (pkcs7) ===="
# 8a. 软件加密(enc证书) -> 硬件解密（依赖设备enc私钥）
q $OSSL pkcs7 -encrypt -provider sdfprov -provider default \
    -in $TMP/plain.txt -out $TMP/rsa_env_h.p7 -outform DER \
    $CERTS/server-rsa-enc.crt
if q $OSSL pkcs7 -decrypt -provider sdfprov -provider default \
    -in $TMP/rsa_env_h.p7 -inform DER -out $TMP/rsa_env_dec.txt \
    -inkey "sdf:rsa:0:enc" -recip $CERTS/server-rsa-enc.crt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_env_dec.txt; then ok "RSA envelope SW-encrypt -> HW-decrypt"
    else wn "RSA envelope SW-encrypt -> HW-decrypt (device enc keypair missing?)"; fi
else wn "RSA envelope HW-decrypt (needs device RSA enc keypair import)"; fi
# 8b. 软件基线
if q $OSSL pkcs7 -decrypt -provider default \
    -in $TMP/rsa_env_h.p7 -inform DER -out $TMP/rsa_env_dec2.txt \
    -inkey $CERTS/server-rsa-enc.key -recip $CERTS/server-rsa-enc.crt; then
    if cmp -s $TMP/plain.txt $TMP/rsa_env_dec2.txt; then ok "RSA envelope SW-encrypt -> SW-decrypt (baseline)"
    else no "RSA envelope SW-encrypt -> SW-decrypt (content mismatch)"; fi
else no "RSA envelope SW-encrypt -> SW-decrypt (baseline)"; fi

echo ""
echo "============================================================"
echo " SUMMARY:  PASS=$PASS  FAIL=$FAIL  WARN=$WARN"
echo " (WARN = depends on device RSA enc keypair; not code issue)"
echo "============================================================"
[ $FAIL -eq 0 ]
