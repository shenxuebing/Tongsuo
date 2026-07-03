@echo off
REM ============================================================
REM SDF Provider 签名验签 + 数字信封 全场景测试
REM
REM 覆盖：
REM   1. dgst SM2 签名/验签（SDF 硬件私钥 + 证书公钥）
REM   2. dgst RSA 签名/验签（SDF 硬件私钥 + 证书公钥）
REM   3. pkcs7 SM2 数字信封封装（sm2/server_enc.crt）+ 解封（sdf:sm2:0:enc）
REM   4. pkcs7 RSA 数字信封封装（server-rsa-enc.crt）+ 解封（sdf:rsa:0:enc）
REM
REM 前置条件：
REM   - SDF 设备已连接，byzk0018.dll 可加载
REM   - 0 号索引已导入 SM2 签名/加密密钥对（与 sm2/server_*.crt 匹配）
REM   - 0 号索引已导入 RSA 签名/加密密钥对（与 server-rsa-*.crt 匹配）
REM   - openssl.cnf 中 sdf_use_loadmodule=1 且 sdf_lib_path 正确
REM
REM 用法：在 apps 目录下执行  test_sdf_sign_envelope.bat
REM ============================================================

setlocal enabledelayedexpansion
set OPENSSL_CONF=%~dp0openssl.cnf
set OSSL=%~dp0openssl.exe
set CERTS=..\test\certs
set TMP=%TEMP%\sdf_test
if not exist %TMP% mkdir %TMP%

set PASS=0
set FAIL=0

echo ============================================================
echo  SDF Provider 签名验签 + 数字信封 测试
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo  TMP=%TMP%
echo ============================================================
echo.

REM ------------------------------------------------------------
echo [1/4] dgst SM2 签名 (SDF 硬件私钥 sdf:sm2:0:sign)
REM ------------------------------------------------------------
echo sm2 test message > %TMP%\data.txt
%OSSL% dgst -sm3 -provider sdfprov -provider default ^
    -sign "sdf:sm2:0:sign" -out %TMP%\sm2_sig.bin %TMP%\data.txt 2>%TMP%\1.log
if %errorlevel% neq 0 (
    echo   [FAIL] SM2 签名失败
    type %TMP%\1.log
    set /a FAIL+=1
) else (
    echo   [OK]   SM2 签名成功
    set /a PASS+=1
)

REM ------------------------------------------------------------
echo [2/4] dgst SM2 验签 (证书公钥)
REM ------------------------------------------------------------
%OSSL% x509 -in %CERTS%\sm2\server_sign.crt -pubkey -noout > %TMP%\sm2_pub.pem 2>nul
%OSSL% dgst -sm3 -provider sdfprov -provider default ^
    -verify %TMP%\sm2_pub.pem -signature %TMP%\sm2_sig.bin %TMP%\data.txt 2>%TMP%\2.log | findstr /C:"Verified OK" >nul
if %errorlevel% equ 0 (
    echo   [OK]   SM2 验签通过
    set /a PASS+=1
) else (
    echo   [FAIL] SM2 验签失败
    type %TMP%\2.log
    set /a FAIL+=1
)

REM ------------------------------------------------------------
echo [3/4] dgst RSA 签名 (SDF 硬件私钥 sdf:rsa:0:sign)
REM ------------------------------------------------------------
%OSSL% dgst -sha256 -provider sdfprov -provider default ^
    -sign "sdf:rsa:0:sign" -out %TMP%\rsa_sig.bin %TMP%\data.txt 2>%TMP%\3.log
if %errorlevel% neq 0 (
    echo   [FAIL] RSA 签名失败
    type %TMP%\3.log
    set /a FAIL+=1
) else (
    echo   [OK]   RSA 签名成功
    set /a PASS+=1
)

REM ------------------------------------------------------------
echo [4/4] dgst RSA 验签 (证书公钥)
REM ------------------------------------------------------------
%OSSL% x509 -in %CERTS%\server-rsa-sign.crt -pubkey -noout > %TMP%\rsa_pub.pem 2>nul
%OSSL% dgst -sha256 -provider default ^
    -verify %TMP%\rsa_pub.pem -signature %TMP%\rsa_sig.bin %TMP%\data.txt 2>%TMP%\4.log | findstr /C:"Verified OK" >nul
if %errorlevel% equ 0 (
    echo   [OK]   RSA 验签通过
    set /a PASS+=1
) else (
    echo   [FAIL] RSA 验签失败
    type %TMP%\4.log
    set /a FAIL+=1
)

echo.
echo ============================================================
echo  PKCS7 数字信封测试
echo ============================================================
echo.

REM ------------------------------------------------------------
echo [5/8] pkcs7 SM2 数字信封封装 (sm2/server_enc.crt)
REM ------------------------------------------------------------
<nul set /p =sm2 envelope content> %TMP%\env_plain.txt
%OSSL% pkcs7 -encrypt -provider sdfprov -provider default ^
    -in %TMP%\env_plain.txt -out %TMP%\sm2_env.p7 -outform DER ^
    %CERTS%\sm2\server_enc.crt 2>%TMP%\5.log
if %errorlevel% neq 0 (
    echo   [FAIL] SM2 信封封装失败
    type %TMP%\5.log
    set /a FAIL+=1
) else (
    echo   [OK]   SM2 信封封装成功
    set /a PASS+=1
)

REM ------------------------------------------------------------
echo [6/8] pkcs7 SM2 数字信封解封 (SDF 私钥 sdf:sm2:0:enc)
REM ------------------------------------------------------------
%OSSL% pkcs7 -decrypt -provider sdfprov -provider default ^
    -in %TMP%\sm2_env.p7 -inform DER -out %TMP%\sm2_dec.txt ^
    -inkey "sdf:sm2:0:enc" -recip %CERTS%\sm2\server_enc.crt 2>%TMP%\6.log
fc /b %TMP%\env_plain.txt %TMP%\sm2_dec.txt >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]   SM2 信封解封成功，内容匹配
    set /a PASS+=1
) else (
    echo   [FAIL] SM2 信封解封失败或内容不匹配
    type %TMP%\6.log
    set /a FAIL+=1
)

REM ------------------------------------------------------------
echo [7/8] pkcs7 RSA 数字信封封装 (server-rsa-enc.crt)
REM ------------------------------------------------------------
<nul set /p =rsa envelope content> %TMP%\env_plain2.txt
%OSSL% pkcs7 -encrypt -provider sdfprov -provider default ^
    -in %TMP%\env_plain2.txt -out %TMP%\rsa_env.p7 -outform DER ^
    %CERTS%\server-rsa-enc.crt 2>%TMP%\7.log
if %errorlevel% neq 0 (
    echo   [FAIL] RSA 信封封装失败
    type %TMP%\7.log
    set /a FAIL+=1
) else (
    echo   [OK]   RSA 信封封装成功
    set /a PASS+=1
)

REM ------------------------------------------------------------
echo [8/8] pkcs7 RSA 数字信封解封 (SDF 私钥 sdf:rsa:0:enc)
REM    注：此项要求 SDF 设备 0 号索引的 RSA 加密密钥与
REM    server-rsa-enc.crt 匹配；若设备未导入 RSA enc 密钥对，
REM    此项会失败，属于设备配置问题，非代码问题。
REM ------------------------------------------------------------
%OSSL% pkcs7 -decrypt -provider sdfprov -provider default ^
    -in %TMP%\rsa_env.p7 -inform DER -out %TMP%\rsa_dec.txt ^
    -inkey "sdf:rsa:0:enc" -recip %CERTS%\server-rsa-enc.crt 2>%TMP%\8.log
fc /b %TMP%\env_plain2.txt %TMP%\rsa_dec.txt >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]   RSA 信封解封成功，内容匹配
    set /a PASS+=1
) else (
    echo   [WARN] RSA 信封解封失败（请确认设备 0 号索引已导入与
    echo          server-rsa-enc.crt 匹配的 RSA 加密密钥对）
    type %TMP%\8.log
    set /a FAIL+=1
)

echo.
echo ============================================================
echo  测试结果：PASS=%PASS%  FAIL=%FAIL%
echo ============================================================
if %FAIL% neq 0 exit /b 1
endlocal
exit /b 0
