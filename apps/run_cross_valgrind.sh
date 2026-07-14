#!/usr/bin/env bash
# Valgrind 内存检测: SM2/RSA P1/P7/信封 硬件操作
set -u

cd "$(dirname "$0")"
export OPENSSL_CONF="$(pwd)/openssl_linux.cnf"
export SDF_LIB_PATH="$(pwd)/libbyzk0018.so"
export BYZK0018_SKIP_OPENSSL_PROVIDER_INIT="${BYZK0018_SKIP_OPENSSL_PROVIDER_INIT:-1}"
export SDF_MODULE_PASSWORD="88888888"
export SDF_USE_LOADMODULE="1"

CERTS="../test/certs"
OUT="../valgrind_out"
mkdir -p "$OUT"
printf 'cross verify payload 0123456789' > /tmp/plain.txt

VGOPTS="--leak-check=full --show-leak-kinds=all --track-origins=yes --run-libc-freeres=no"
# 屏蔽 OpenSSL atexit 残留 + 厂商库/动态链接器已知一次性泄漏
VGOPTS="$VGOPTS --suppressions=$(pwd)/sdf_provider_supp.supp"

# 运行并输出内存摘要
run_vg() {
    local label="$1"; shift
    local out="$OUT/${label}.vout"
    valgrind $VGOPTS --log-file="$out" ./openssl "$@" >/dev/null 2>&1
    if [ ! -f "$out" ]; then
        printf "  %-26s [未生成vout]\n" "$label"
        return
    fi
    local dl pl code_hit errs
    dl=$(grep 'definitely lost' "$out" | tail -1 | sed 's/.*definitely lost://;s/^ *//')
    pl=$(grep '  possibly lost' "$out" | tail -1 | sed 's/.*possibly lost://;s/^ *//')
    code_hit=$(grep -c 'providers/\|crypto/sdf\|crypto/sm2' "$out")
    errs=$(grep 'ERROR SUMMARY' "$out" | tail -1 | sed 's/.*ERROR SUMMARY: //')
    printf "  %-26s def=%-16s pos=%-16s 代码层=%-4s errs=%s\n" "$label" "$dl" "$pl" "$code_hit" "$errs"
}

echo "============================================================"
echo " Valgrind 内存检测: SDF Provider 硬件操作"
echo "============================================================"

# 准备测试数据
echo "--- 准备测试数据 ---"
run_vg sm2_p1_sign dgst -sm3 -provider sdfprov -provider default \
    -sign 'sdf:sm2:0:sign' -out /tmp/sm2_p1.bin /tmp/plain.txt

# SM2 加密数据(软件) 供硬件解密
./openssl pkeyutl -provider default -encrypt -pubin \
    -inkey "$CERTS/sm2/server_enc_pub.pem" \
    -in /tmp/plain.txt -out /tmp/sm2_ct.bin 2>/dev/null
run_vg sm2_hw_decrypt pkeyutl -provider sdfprov -provider default -decrypt \
    -inkey 'sdf:sm2:0:enc' -in /tmp/sm2_ct.bin -out /tmp/sm2_pt.txt

run_vg sm2_p7_sign pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached \
    -in /tmp/plain.txt -out /tmp/sm2_p7.p7 -outform DER \
    -signer "$CERTS/sm2/server_sign.crt" -inkey 'sdf:sm2:0:sign'

# SM2 信封(软件加密) 供硬件解密
./openssl pkcs7 -encrypt -gmt0010 -provider default \
    -in /tmp/plain.txt -out /tmp/sm2_env.p7 -outform DER "$CERTS/sm2/server_enc.crt" 2>/dev/null
run_vg sm2_env_decrypt pkcs7 -decrypt -provider sdfprov -provider default \
    -in /tmp/sm2_env.p7 -inform DER -out /tmp/sm2_envpt.txt \
    -inkey 'sdf:sm2:0:enc' -recip "$CERTS/sm2/server_enc.crt"

echo ""
echo "--- RSA 场景 ---"
run_vg rsa_p1_sign dgst -sha256 -provider sdfprov -provider default \
    -sign 'sdf:rsa:0:sign' -out /tmp/rsa_p1.bin /tmp/plain.txt

# RSA 加密数据(软件) 供硬件解密
./openssl pkeyutl -provider default -encrypt -certin \
    -inkey "$CERTS/server-rsa-enc.crt" \
    -in /tmp/plain.txt -out /tmp/rsa_ct.bin 2>/dev/null
run_vg rsa_hw_decrypt pkeyutl -provider sdfprov -provider default -decrypt \
    -inkey 'sdf:rsa:0:enc' -in /tmp/rsa_ct.bin -out /tmp/rsa_pt.txt

run_vg rsa_p7_sign pkcs7 -sign -provider sdfprov -provider default -detached \
    -in /tmp/plain.txt -out /tmp/rsa_p7.p7 -outform DER \
    -signer "$CERTS/server-rsa-sign.crt" -inkey 'sdf:rsa:0:sign'

# RSA 信封(软件加密) 供硬件解密
./openssl smime -encrypt -binary -outform DER \
    -in /tmp/plain.txt -out /tmp/rsa_env.p7 "$CERTS/server-rsa-enc.crt" 2>/dev/null
run_vg rsa_env_decrypt smime -decrypt -inform DER \
    -in /tmp/rsa_env.p7 -recip "$CERTS/server-rsa-enc.crt" \
    -inkey 'sdf:rsa:0:enc' -provider sdfprov -provider default -out /tmp/rsa_envpt.txt

echo ""
echo "============================================================"
echo " 说明:"
echo "   def   = definitely lost (确定性泄漏,必须修复)"
echo "   pos   = possibly lost (可能泄漏)"
echo "   代码层 = vout堆栈中含 providers//crypto/ 的记录数"
echo "          >0 需检查是否你的代码泄漏; =0 说明是厂商库/系统库"
echo "============================================================"
