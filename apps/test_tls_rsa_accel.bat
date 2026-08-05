@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

set "RAW_ARGS=%*"
:parse_args
if "!RAW_ARGS!"=="" goto args_done
for /f "tokens=1,* delims= " %%A in ("!RAW_ARGS!") do (
    set "ONE_ARG=%%~A"
    set "RAW_ARGS=%%~B"
)
for /f "tokens=1,* delims==" %%K in ("!ONE_ARG!") do (
    if not "%%~L"=="" set "%%~K=%%~L"
)
goto parse_args
:args_done

if "%OPENSSL_CONF%"=="" set "OPENSSL_CONF=%~dp0openssl.cnf"
set "OSSL=%~dp0openssl.exe"
set "CERTS=..\test\certs"
set "OUTDIR=%CD%"

:: index: 1=server RSA2048, 2=client RSA2048
if "%SERVER_RSA_IDX%"=="" set "SERVER_RSA_IDX=1"
if "%CLIENT_RSA_IDX%"=="" set "CLIENT_RSA_IDX=2"

if "%RSA_SIGN_CERT%"=="" set "RSA_SIGN_CERT=%CERTS%\server-rsa-sign.crt"
if "%RSA_SIGN_KEY%"==""  set "RSA_SIGN_KEY=%CERTS%\server-rsa-sign.key"
if "%RSA_ENC_CERT%"==""  set "RSA_ENC_CERT=%CERTS%\server-rsa-enc.crt"
if "%RSA_ENC_KEY%"==""   set "RSA_ENC_KEY=%CERTS%\server-rsa-enc.key"
if "%CLIENT_SIGN_CERT%"=="" set "CLIENT_SIGN_CERT=%CERTS%\client-rsa-sign.crt"
if "%CLIENT_SIGN_KEY%"==""  set "CLIENT_SIGN_KEY=%CERTS%\client-rsa-sign.key"
if "%CLIENT_ENC_CERT%"==""  set "CLIENT_ENC_CERT=%CERTS%\client-rsa-enc.crt"
if "%CLIENT_ENC_KEY%"==""   set "CLIENT_ENC_KEY=%CERTS%\client-rsa-enc.key"

if "%TLS_VERSION%"=="" set "TLS_VERSION=-tls1_2"
if "%ECDHE_CIPHER%"=="" set "ECDHE_CIPHER=ECDHE-RSA-AES128-GCM-SHA256"
if "%RSA_CIPHER%"=="" set "RSA_CIPHER=AES128-SHA"

set PASS=0
set FAIL=0
set NUM=0

echo ============================================================
echo  TLS RSA Acceleration Test (with mTLS cross verification)
echo  Server RSA2048 -^> index !SERVER_RSA_IDX!
echo  Client RSA2048 -^> index !CLIENT_RSA_IDX!
echo ============================================================

:: ============================================================
:: Import keys before testing
:: ============================================================
echo.
echo ==== Import RSA keys to device ====
"%OSSL%" sdf -delsm2key -index !SERVER_RSA_IDX! -type sign >nul 2>&1
"%OSSL%" sdf -delsm2key -index !SERVER_RSA_IDX! -type enc  >nul 2>&1
"%OSSL%" sdf -delsm2key -index !CLIENT_RSA_IDX! -type sign >nul 2>&1
"%OSSL%" sdf -delsm2key -index !CLIENT_RSA_IDX! -type enc  >nul 2>&1

echo [CMD] "%OSSL%" sdf -importrsakey -index !SERVER_RSA_IDX! -type sign -inkey "!RSA_SIGN_KEY!"
"%OSSL%" sdf -importrsakey -index !SERVER_RSA_IDX! -type sign -inkey "!RSA_SIGN_KEY!" >nul 2>&1
echo [CMD] "%OSSL%" sdf -importrsakey -index !SERVER_RSA_IDX! -type enc -inkey "!RSA_ENC_KEY!"
"%OSSL%" sdf -importrsakey -index !SERVER_RSA_IDX! -type enc  -inkey "!RSA_ENC_KEY!"  >nul 2>&1
echo [CMD] "%OSSL%" sdf -importrsakey -index !CLIENT_RSA_IDX! -type sign -inkey "!CLIENT_SIGN_KEY!"
"%OSSL%" sdf -importrsakey -index !CLIENT_RSA_IDX! -type sign -inkey "!CLIENT_SIGN_KEY!" >nul 2>&1
echo [CMD] "%OSSL%" sdf -importrsakey -index !CLIENT_RSA_IDX! -type enc -inkey "!CLIENT_ENC_KEY!"
"%OSSL%" sdf -importrsakey -index !CLIENT_RSA_IDX! -type enc  -inkey "!CLIENT_ENC_KEY!"  >nul 2>&1

taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
ping -n 3 127.0.0.1 >nul 2>&1

:: ============================================================
:: 1. ECDHE-RSA HW server-sign
:: ============================================================
set /a NUM+=1
echo.
echo [!NUM!] ECDHE-RSA HW server-sign (HW server, SW client)
call :handshake 25211 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "sdf:rsa:!SERVER_RSA_IDX!:sign" "-provider sdfprov -provider default" "" "" ""

:: 2. ECDHE-RSA SW server-sign (baseline)
set /a NUM+=1
echo.
echo [!NUM!] ECDHE-RSA SW server-sign (baseline)
call :handshake 25212 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "!RSA_SIGN_KEY!" "" "" "" ""

:: 3. TLS-RSA HW server-decrypt
set /a NUM+=1
echo.
echo [!NUM!] TLS-RSA HW server-decrypt (HW server, SW client)
call :handshake 25213 "!RSA_CIPHER!" "!RSA_ENC_CERT!" "sdf:rsa:!SERVER_RSA_IDX!:enc" "-provider sdfprov -provider default" "" "" ""

:: 4. TLS-RSA SW server-decrypt (baseline)
set /a NUM+=1
echo.
echo [!NUM!] TLS-RSA SW server-decrypt (baseline)
call :handshake 25214 "!RSA_CIPHER!" "!RSA_ENC_CERT!" "!RSA_ENC_KEY!" "" "" "" ""

:: 5. mTLS HW server + HW client
set /a NUM+=1
echo.
echo [!NUM!] mTLS HW server + HW client (both HW sign)
call :handshake 25215 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "sdf:rsa:!SERVER_RSA_IDX!:sign" "-provider sdfprov -provider default" "!CLIENT_SIGN_CERT!" "sdf:rsa:!CLIENT_RSA_IDX!:sign" "-provider sdfprov -provider default" "-Verify 2"

:: 6. mTLS HW server + SW client
set /a NUM+=1
echo.
echo [!NUM!] mTLS HW server + SW client
call :handshake 25216 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "sdf:rsa:!SERVER_RSA_IDX!:sign" "-provider sdfprov -provider default" "!CLIENT_SIGN_CERT!" "!CLIENT_SIGN_KEY!" "" "-Verify 2"

:: 7. mTLS SW server + HW client
set /a NUM+=1
echo.
echo [!NUM!] mTLS SW server + HW client
call :handshake 25217 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "!RSA_SIGN_KEY!" "" "!CLIENT_SIGN_CERT!" "sdf:rsa:!CLIENT_RSA_IDX!:sign" "-provider sdfprov -provider default" "-Verify 2"

:: 8. mTLS SW server + SW client (baseline)
set /a NUM+=1
echo.
echo [!NUM!] mTLS SW server + SW client (baseline)
call :handshake 25218 "!ECDHE_CIPHER!" "!RSA_SIGN_CERT!" "!RSA_SIGN_KEY!" "" "!CLIENT_SIGN_CERT!" "!CLIENT_SIGN_KEY!" "" "-Verify 2"

:: ============================================================
echo.
echo ============================================================
echo  SUMMARY: PASS=!PASS! / !NUM!, FAIL=!FAIL! / !NUM!
echo ============================================================

taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
if !FAIL! gtr 0 exit /b 1
exit /b 0

:: ============================================================
::  :handshake
::  %1=port %2=cipher %3=server_cert %4=server_key %5=server_prov
::  %6=client_cert %7=client_key %8=client_prov %9=verify
:: ============================================================
:handshake
set "HP=%~1"
set "HC=%~2"
set "SCERT=%~3"
set "SKEY=%~4"
set "SPROV=%~5"
set "CCERT=%~6"
set "CKEY=%~7"
set "CPROV=%~8"
set "VERIFY=%~9"
set "SF=%OUTDIR%\tls_svr_%HP%.txt"
set "CF=%OUTDIR%\tls_cli_%HP%.txt"

set "SCMD="%OSSL%" s_server -accept %HP% %TLS_VERSION% -cipher %HC% -cert "%SCERT%" -key %SKEY% %SPROV% -www"
if not "%VERIFY%"=="" set "SCMD=!SCMD! %VERIFY%"

set "CCMD="%OSSL%" s_client -connect 127.0.0.1:%HP% %TLS_VERSION% -cipher %HC%"
if not "%CCERT%"=="" set "CCMD=!CCMD! -cert "%CCERT%""
if not "%CKEY%"==""  set "CCMD=!CCMD! -key %CKEY%"
if not "%CPROV%"=="" set "CCMD=!CCMD! %CPROV%"

echo     [CMD][server] !SCMD!
start "" /b cmd /c "!SCMD! > "%SF%" 2>&1"
if "%SPROV%"=="-provider sdfprov -provider default" (
    ping -n 5 127.0.0.1 >nul 2>&1
) else (
    ping -n 3 127.0.0.1 >nul 2>&1
)

echo     [CMD][client] echo Q ^| !CCMD!
start "" /b cmd /c "echo Q| !CCMD! > "%CF%" 2>&1"

set /a TIMEOUT=0
:wait_loop
ping -n 2 127.0.0.1 >nul 2>&1
set /a TIMEOUT+=1
if !TIMEOUT! GEQ 15 goto handshake_done
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 goto handshake_done
goto wait_loop

:handshake_done
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
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
del /f /q yj.db-shm yj.db-wal >nul 2>&1
if "%SPROV%"=="-provider sdfprov -provider default" (
    ping -n 4 127.0.0.1 >nul 2>&1
) else (
    ping -n 2 127.0.0.1 >nul 2>&1
)
goto :eof
