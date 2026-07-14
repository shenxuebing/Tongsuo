#!/usr/bin/env bash
#
# NTLS 单场景 Valgrind 内存检测
# 测试 ECC-SM2-SM4-CBC-SM3 / ECDHE-SM2-SM4-CBC-SM3 握手
#
set -u

export OPENSSL_CONF="${OPENSSL_CONF:-$(pwd)/openssl_linux.cnf}"
export SDF_LIB_PATH="${SDF_LIB_PATH:-$(pwd)/libbyzk0018.so}"
export SDF_MODULE_PASSWORD="${SDF_MODULE_PASSWORD:-88888888}"
export SDF_USE_LOADMODULE="${SDF_USE_LOADMODULE:-1}"
export BYZK0018_SKIP_OPENSSL_PROVIDER_INIT="${BYZK0018_SKIP_OPENSSL_PROVIDER_INIT:-1}"

CERTS="../test/certs/sm2"
CAFILE="$CERTS/chain-ca.crt"
OUTDIR="../valgrind_out"
mkdir -p "$OUTDIR"

VG="valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --run-libc-freeres=no"

# 参数: cipher suite, server_key_type, client_key_type, port, label
run_ntls_vg() {
    local cipher="$1"
    local svr_kt="$2"
    local cli_kt="$3"
    local port="$4"
    local label="$5"

    local svr_sign_key svr_enc_key cli_sign_key cli_enc_key
    local svr_prov="" cli_prov=""

    if [ "$svr_kt" = "hw" ]; then
        svr_sign_key="sdf:key=0;type=sign"
        svr_enc_key="sdf:key=0;type=enc"
        svr_prov="-provider sdfprov -provider default"
    else
        svr_sign_key="$CERTS/server_sign.key"
        svr_enc_key="$CERTS/server_enc.key"
    fi

    if [ "$cli_kt" = "hw" ]; then
        cli_sign_key="sdf:key=1;type=sign"
        cli_enc_key="sdf:key=1;type=enc"
        cli_prov="-provider sdfprov -provider default"
    else
        cli_sign_key="$CERTS/client_sign.key"
        cli_enc_key="$CERTS/client_enc.key"
    fi

    echo ""
    echo "============================================================"
    echo " [$label] $cipher | Svr:$svr_kt | Cli:$cli_kt (port $port)"
    echo "============================================================"

    # 启动 server (Valgrind 包装)
    $VG --log-file="$OUTDIR/${label}_server.vout" \
        ./openssl s_server -ntls -enable_ntls -accept $port \
        -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
        -sign_key "$svr_sign_key" -enc_key "$svr_enc_key" \
        $svr_prov -www -CAfile $CAFILE -cipher $cipher \
        >"$OUTDIR/${label}_server.out" 2>&1 &
    local svrpid=$!

    sleep 4

    # 启动 client (Valgrind 包装)
    printf 'Q\n' | $VG --log-file="$OUTDIR/${label}_client.vout" \
        ./openssl s_client -ntls -enable_ntls -connect 127.0.0.1:$port \
        -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt \
        -sign_key "$cli_sign_key" -enc_key "$cli_enc_key" \
        $cli_prov -CAfile $CAFILE -cipher $cipher \
        >"$OUTDIR/${label}_client.out" 2>&1

    # 检查握手结果
    if grep -q "Cipher is" "$OUTDIR/${label}_client.out" 2>/dev/null; then
        echo "  [握手成功] $(grep 'Cipher is' $OUTDIR/${label}_client.out)"
        grep "Protocol" "$OUTDIR/${label}_client.out" 2>/dev/null | sed 's/^/    /'
    else
        echo "  [握手失败]"
        grep -i "error" "$OUTDIR/${label}_client.out" 2>/dev/null | head -2 | sed 's/^/    Client: /'
        grep -i "error" "$OUTDIR/${label}_server.out" 2>/dev/null | head -2 | sed 's/^/    Server: /'
    fi

    kill $svrpid 2>/dev/null
    wait $svrpid 2>/dev/null
    sleep 2

    # 内存摘要
    local s_errs c_errs
    s_errs=$(grep 'ERROR SUMMARY' "$OUTDIR/${label}_server.vout" 2>/dev/null | sed 's/.*ERROR SUMMARY: //')
    c_errs=$(grep 'ERROR SUMMARY' "$OUTDIR/${label}_client.vout" 2>/dev/null | sed 's/.*ERROR SUMMARY: //')
    echo "  [Valgrind] server: $s_errs"
    echo "  [Valgrind] client: $c_errs"
}

echo "============================================================"
echo " NTLS Valgrind 内存检测"
echo " OPENSSL_CONF=$OPENSSL_CONF"
echo "============================================================"

# 测试矩阵: ECC-SM2 + ECDHE-SM2, 各跑 SW/SW 和 HW/HW
run_ntls_vg ECC-SM2-SM4-CBC-SM3   sw sw 25301 ecc_sw_sw
run_ntls_vg ECC-SM2-SM4-CBC-SM3   hw hw 25302 ecc_hw_hw
run_ntls_vg ECDHE-SM2-SM4-CBC-SM3 sw sw 25303 ecdhe_sw_sw
run_ntls_vg ECDHE-SM2-SM4-CBC-SM3 hw hw 25304 ecdhe_hw_hw

# 汇总
echo ""
echo "============================================================"
echo " 内存泄漏汇总 (排除厂商库/动态链接器误报)"
echo "============================================================"
echo "--- 含 providers/ 或 crypto/sdf 的泄漏记录(你的代码) ---"
for f in $OUTDIR/*_server.vout $OUTDIR/*_client.vout; do
    [ -f "$f" ] || continue
    # 找泄漏块,检查堆栈是否含 provider 代码
    hit=$(grep -c 'providers/\|crypto/sdf\|crypto/sm' "$f" 2>/dev/null)
    if [ "$hit" -gt 0 ]; then
        echo ">>> $f 有 $hit 处疑似代码泄漏,需检查"
    fi
done
echo "(无 >>> 提示 = 你的代码无泄漏)"

echo ""
echo "--- 各场景 ERROR SUMMARY ---"
for f in $OUTDIR/ecc_*_server.vout $OUTDIR/ecc_*_client.vout $OUTDIR/ecdhe_*_server.vout $OUTDIR/ecdhe_*_client.vout; do
    [ -f "$f" ] || continue
    label=$(basename "$f" .vout)
    errs=$(grep 'ERROR SUMMARY' "$f" 2>/dev/null | sed 's/.*ERROR SUMMARY: //')
    printf "  %-35s %s\n" "$label" "$errs"
done
