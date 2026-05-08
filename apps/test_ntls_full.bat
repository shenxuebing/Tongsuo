@echo off
chcp 65001 >nul 2>&1
call "D:\Visual Studio 2022\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1
cd /d E:\vs2022workspace\Tongsuo\apps

set PASS=0
set FAIL=0
set NUM=0
if not exist ..\ntls_out mkdir ..\ntls_out
set "CERTS=..\test\certs\sm2"
set "CAFILE=%CERTS%\chain-ca.crt"

echo.
echo ================================================================
echo   NTLS SM2 密码套件全组合测试
echo   2 密码套件 x 4 密钥组合 = 8 测试场景
echo ================================================================

taskkill /f /im openssl.exe >nul 2>&1

:: ============================================================
::  1. ECC-SM2-SM4-CBC-SM3 | Svr: SW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 | Svr:SW | Cli:SW
call :handshake 25101 ECC-SM2-SM4-CBC-SM3 ^
    "-provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key" ^
    "-provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key"

:: ============================================================
::  2. ECC-SM2-SM4-CBC-SM3 | Svr: HW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 | Svr:HW | Cli:SW
call :handshake 25102 ECC-SM2-SM4-CBC-SM3 ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\"" ^
    "-provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key"

:: ============================================================
::  3. ECC-SM2-SM4-CBC-SM3 | Svr: SW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 | Svr:SW | Cli:HW
call :handshake 25103 ECC-SM2-SM4-CBC-SM3 ^
    "-provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key" ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\""

:: ============================================================
::  4. ECC-SM2-SM4-CBC-SM3 | Svr: HW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 | Svr:HW | Cli:HW
call :handshake 25104 ECC-SM2-SM4-CBC-SM3 ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\"" ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\""

:: ============================================================
::  5. ECDHE-SM2-SM4-CBC-SM3 | Svr: SW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 | Svr:SW | Cli:SW
call :handshake 25105 ECDHE-SM2-SM4-CBC-SM3 ^
    "-provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key" ^
    "-provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key"

:: ============================================================
::  6. ECDHE-SM2-SM4-CBC-SM3 | Svr: HW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 | Svr:HW | Cli:SW
call :handshake 25106 ECDHE-SM2-SM4-CBC-SM3 ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\"" ^
    "-provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key"

:: ============================================================
::  7. ECDHE-SM2-SM4-CBC-SM3 | Svr: SW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 | Svr:SW | Cli:HW
call :handshake 25107 ECDHE-SM2-SM4-CBC-SM3 ^
    "-provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key" ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\""

:: ============================================================
::  8. ECDHE-SM2-SM4-CBC-SM3 | Svr: HW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 | Svr:HW | Cli:HW
call :handshake 25108 ECDHE-SM2-SM4-CBC-SM3 ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\"" ^
    "-provider sdfprov -provider default" ^
    "-sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key \"sdf:sm2:0:sign\" -enc_key \"sdf:sm2:0:enc\""

:: ============================================================
:: 汇总
:: ============================================================
echo.
echo ================================================================
echo   测试汇总:  通过 %PASS% / %NUM%,  失败 %FAIL% / %NUM%
echo ================================================================

del /q ..\ntls_out\* >nul 2>&1
rmdir ..\ntls_out >nul 2>&1
taskkill /f /im openssl.exe >nul 2>&1
exit /b

:: ============================================================
::  :handshake 子程序
::  %1=端口  %2=密码套件  %3=服务端provider  %4=服务端key参数
::  %5=客户端provider  %6=客户端key参数
:: ============================================================
:handshake
set "HP=%~1"
set "HC=%~2"
set "SP=%~3"
set "SK=%~4"
set "CP=%~5"
set "CK=%~6"

set "SF=..\ntls_out\svr_%HP%.txt"
set "CF=..\ntls_out\cli_%HP%.txt"

start /b openssl.exe s_server -ntls -enable_ntls -accept %HP% %SK% %SP% -Verify 1 -CAfile %CAFILE% -cipher %HC% > "%SF%" 2>&1

ping -n 4 127.0.0.1 >nul 2>&1

echo Q | openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:%HP% %CK% %CP% -CAfile %CAFILE% -cipher %HC% > "%CF%" 2>&1

findstr /C:"Cipher is" "%CF%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [PASS]
    for /f "tokens=*" %%i in ('findstr /C:"Cipher is" "%CF%"') do echo     %%i
    for /f "tokens=*" %%i in ('findstr /C:"Protocol" "%CF%"') do echo     %%i
    set /a PASS+=1
) else (
    echo     [FAIL]
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%CF%" 2^>nul') do echo     Client: %%i
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%SF%" 2^>nul') do echo     Server: %%i
    set /a FAIL+=1
)

taskkill /f /im openssl.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul 2>&1
goto :eof
