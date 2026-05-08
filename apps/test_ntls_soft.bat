@echo off
chcp 65001 >nul 2>&1
call "D:\Visual Studio 2022\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1
cd /d E:\vs2022workspace\Tongsuo\apps

set "CERTS=..\test\certs\sm2"
set "CAFILE=%CERTS%\chain-ca.crt"

echo.
echo ================================================================
echo   NTLS 纯软件测试 (不需要 SDF 硬件)
echo   证书: %CERTS%
echo   ECC-SM2-SM4-CBC-SM3 + ECDHE-SM2-SM4-CBC-SM3
echo ================================================================

taskkill /f /im openssl.exe >nul 2>&1

:: ---- ECC-SM2 ----
echo.
echo  [1] ECC-SM2-SM4-CBC-SM3 (软件密钥)
start /b openssl.exe s_server -ntls -enable_ntls -accept 25201 ^
    -sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt ^
    -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key ^
    -provider default -CAfile %CAFILE% ^
    -cipher ECC-SM2-SM4-CBC-SM3 > ..\ntls_sw_svr.txt 2>&1
ping -n 4 127.0.0.1 >nul 2>&1
echo Q | openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:25201 ^
    -sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt ^
    -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key ^
    -provider default -CAfile %CAFILE% ^
    -cipher ECC-SM2-SM4-CBC-SM3 > ..\ntls_sw_cli.txt 2>&1
findstr /C:"Cipher is" ..\ntls_sw_cli.txt >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [PASS]
    findstr /C:"Cipher is" ..\ntls_sw_cli.txt
) else (
    echo     [FAIL]
    findstr /i /C:"error" ..\ntls_sw_cli.txt 2>nul
)
taskkill /f /im openssl.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul 2>&1

:: ---- ECDHE-SM2 ----
echo.
echo  [2] ECDHE-SM2-SM4-CBC-SM3 (软件密钥)
start /b openssl.exe s_server -ntls -enable_ntls -accept 25202 ^
    -sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt ^
    -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key ^
    -provider default -CAfile %CAFILE% ^
    -cipher ECDHE-SM2-SM4-CBC-SM3 > ..\ntls_sw_svr.txt 2>&1
ping -n 4 127.0.0.1 >nul 2>&1
echo Q | openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:25202 ^
    -sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt ^
    -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key ^
    -provider default -CAfile %CAFILE% ^
    -cipher ECDHE-SM2-SM4-CBC-SM3 > ..\ntls_sw_cli.txt 2>&1
findstr /C:"Cipher is" ..\ntls_sw_cli.txt >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [PASS]
    findstr /C:"Cipher is" ..\ntls_sw_cli.txt
) else (
    echo     [FAIL]
    findstr /i /C:"error" ..\ntls_sw_cli.txt 2>nul
)

del ..\ntls_sw_svr.txt ..\ntls_sw_cli.txt >nul 2>&1
taskkill /f /im openssl.exe >nul 2>&1
echo.
echo Done.
