@echo off
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

set "OPENSSL_CONF=%OPENSSL_CONF%"
if "%OPENSSL_CONF%"=="" set "OPENSSL_CONF=%~dp0openssl.cnf"
set "OSSL=%~dp0openssl.exe"
set "CERTS=..\test\certs"
set "TMP=%TMP%"
if "%TMP%"=="" set "TMP=%TEMP%\tls_rsa_accel"
if not exist "%TMP%" mkdir "%TMP%"

if "%RSA_SIGN_IDX%"=="" set "RSA_SIGN_IDX=0"
if "%RSA_ENC_IDX%"=="" set "RSA_ENC_IDX=0"
if "%RSA_SIGN_CERT%"=="" set "RSA_SIGN_CERT=%CERTS%\server-rsa-sign.crt"
if "%RSA_ENC_CERT%"=="" set "RSA_ENC_CERT=%CERTS%\server-rsa-enc.crt"
if "%TLS_VERSION%"=="" set "TLS_VERSION=-tls1_2"
if "%ECDHE_CIPHER%"=="" set "ECDHE_CIPHER=ECDHE-RSA-AES128-GCM-SHA256"
if "%RSA_CIPHER%"=="" set "RSA_CIPHER=AES128-SHA"
if "%RSA_SIGALGS%"=="" set "RSA_SIGALGS="
if "%RSA_SIGALGS_COMPAT%"=="" set "RSA_SIGALGS_COMPAT=rsa_pkcs1_sha256"
if "%PORT_SIGN%"=="" set "PORT_SIGN=25203"
if "%PORT_DEC%"=="" set "PORT_DEC=25202"

set PASS=0
set FAIL=0

echo ============================================================
echo  TLS RSA Acceleration Test
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo  RSA_SIGN_IDX=%RSA_SIGN_IDX%  RSA_ENC_IDX=%RSA_ENC_IDX%
echo ============================================================

call :run_ecdhe_rsa_sign "default" "%RSA_SIGALGS%" "%PORT_SIGN%"
call :run_ecdhe_rsa_sign "compat" "%RSA_SIGALGS_COMPAT%" "25205"
call :run_tls_rsa_decrypt

echo.
echo ============================================================
echo  SUMMARY: PASS=!PASS! FAIL=!FAIL!
echo ============================================================

if !FAIL! gtr 0 exit /b 1
exit /b 0

:pass
set "msg=%~1"
echo(  [PASS] !msg!
set /a PASS+=1
exit /b 0

:fail
set "msg=%~1"
echo(  [FAIL] !msg!
set /a FAIL+=1
exit /b 0

:cleanup_port
taskkill /f /im openssl.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul 2>&1
exit /b 0

:run_ecdhe_rsa_sign
set "MODE=%~1"
set "SIGALGS=%~2"
set "PORT=%~3"
set "SF=%TMP%\tls_rsa_sign_server.txt"
set "CF=%TMP%\tls_rsa_sign_client.txt"

echo.
echo ==== ECDHE-RSA server HW-sign (%MODE%) ====
call :cleanup_port

set "SERVER_SIGALGS="
set "CLIENT_SIGALGS="
if not "%SIGALGS%"=="" (
    set "SERVER_SIGALGS=-sigalgs %SIGALGS%"
    set "CLIENT_SIGALGS=-sigalgs %SIGALGS%"
)

start "" /b cmd /c ""%OSSL%" s_server -accept %PORT% %TLS_VERSION% -cipher %ECDHE_CIPHER% !SERVER_SIGALGS! -cert "%RSA_SIGN_CERT%" -key sdf:rsa:%RSA_SIGN_IDX%:sign -provider sdfprov -provider default -www > "%SF%" 2>&1"
ping -n 3 127.0.0.1 >nul 2>&1
start "" /b cmd /c "echo Q| "%OSSL%" s_client -connect 127.0.0.1:%PORT% %TLS_VERSION% -cipher %ECDHE_CIPHER% !CLIENT_SIGALGS! > "%CF%" 2>&1"

set /a TIMEOUT=0
:wait_sign
ping -n 2 127.0.0.1 >nul 2>&1
set /a TIMEOUT+=1
if !TIMEOUT! GEQ 15 goto sign_done
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 goto sign_done
goto wait_sign

:sign_done
findstr /C:"Cipher is %ECDHE_CIPHER%" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :pass "ECDHE-RSA server HW-sign (%MODE%)"
    for /f "tokens=*" %%i in ('findstr /C:"Protocol" "%CF%"') do echo     %%i
    for /f "tokens=*" %%i in ('findstr /C:"Cipher is" "%CF%"') do echo     %%i
) else (
    call :fail "ECDHE-RSA server HW-sign (%MODE%)"
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%CF%" 2^>nul') do echo     Client: %%i
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%SF%" 2^>nul') do echo     Server: %%i
)
call :cleanup_port
exit /b 0

:run_tls_rsa_decrypt
set "SF=%TMP%\tls_rsa_dec_server.txt"
set "CF=%TMP%\tls_rsa_dec_client.txt"

echo.
echo ==== TLS_RSA server HW-decrypt ====
call :cleanup_port

    start "" /b cmd /c ""%OSSL%" s_server -accept %PORT_DEC% %TLS_VERSION% -cipher %RSA_CIPHER% -cert "%RSA_ENC_CERT%" -key sdf:rsa:%RSA_ENC_IDX%:enc -provider sdfprov -provider default -www > "%SF%" 2>&1"
ping -n 3 127.0.0.1 >nul 2>&1
    start "" /b cmd /c "echo Q| "%OSSL%" s_client -connect 127.0.0.1:%PORT_DEC% %TLS_VERSION% -cipher %RSA_CIPHER% > "%CF%" 2>&1"

set /a TIMEOUT=0
:wait_dec
ping -n 2 127.0.0.1 >nul 2>&1
set /a TIMEOUT+=1
if !TIMEOUT! GEQ 15 goto dec_done
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 goto dec_done
goto wait_dec

:dec_done
findstr /C:"Cipher is %RSA_CIPHER%" "%CF%" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :pass "TLS_RSA server HW-decrypt"
    for /f "tokens=*" %%i in ('findstr /C:"Protocol" "%CF%"') do echo     %%i
    for /f "tokens=*" %%i in ('findstr /C:"Cipher is" "%CF%"') do echo     %%i
) else (
    call :fail "TLS_RSA server HW-decrypt"
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%CF%" 2^>nul') do echo     Client: %%i
    for /f "tokens=*" %%i in ('findstr /i /C:"error" "%SF%" 2^>nul') do echo     Server: %%i
)
call :cleanup_port
exit /b 0
