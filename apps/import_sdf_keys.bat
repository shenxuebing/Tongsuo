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

if not exist "%OSSL%" (
    echo [FAIL] cannot find %OSSL%
    exit /b 1
)

if "%SM2_SERVER_IDX%"=="" set "SM2_SERVER_IDX=1"
if "%SM2_CLIENT_IDX%"=="" set "SM2_CLIENT_IDX=2"
if "%SM2_SERVER_SIGN_KEY%"=="" set "SM2_SERVER_SIGN_KEY=%CERTS%\sm2\server_sign.key"
if "%SM2_SERVER_ENC_KEY%"=="" set "SM2_SERVER_ENC_KEY=%CERTS%\sm2\server_enc.key"
if "%SM2_CLIENT_SIGN_KEY%"=="" set "SM2_CLIENT_SIGN_KEY=%CERTS%\sm2\client_sign.key"
if "%SM2_CLIENT_ENC_KEY%"=="" set "SM2_CLIENT_ENC_KEY=%CERTS%\sm2\client_enc.key"

if "%RSA1024_IDX%"=="" set "RSA1024_IDX=1"
if "%RSA2048_IDX%"=="" set "RSA2048_IDX=2"
if "%RSA3072_IDX%"=="" set "RSA3072_IDX=3"
if "%RSA4096_IDX%"=="" set "RSA4096_IDX=4"

if "%RSA1024_SIGN_KEY%"=="" set "RSA1024_SIGN_KEY=%CERTS%\ee-key-1024.pem"
if "%RSA1024_ENC_KEY%"=="" set "RSA1024_ENC_KEY=%CERTS%\ee-key-1024.pem"
if "%RSA2048_SIGN_KEY%"=="" set "RSA2048_SIGN_KEY=%CERTS%\server-rsa-sign.key"
if "%RSA2048_ENC_KEY%"=="" set "RSA2048_ENC_KEY=%CERTS%\server-rsa-enc.key"
if "%RSA3072_SIGN_KEY%"=="" set "RSA3072_SIGN_KEY=%CERTS%\client_3072_sign.key"
if "%RSA3072_ENC_KEY%"=="" set "RSA3072_ENC_KEY=%CERTS%\client_3072_enc.key"
if "%RSA4096_SIGN_KEY%"=="" set "RSA4096_SIGN_KEY=%CERTS%\client_4096_sign.key"
if "%RSA4096_ENC_KEY%"=="" set "RSA4096_ENC_KEY=%CERTS%\client_4096_enc.key"

set PASS=0
set FAIL=0

echo ============================================================
echo  Import SDF keys
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo ============================================================

call :import_sm2 "SM2 server sign" "%SM2_SERVER_IDX%" "sign" "%SM2_SERVER_SIGN_KEY%"
call :import_sm2 "SM2 server enc"  "%SM2_SERVER_IDX%" "enc"  "%SM2_SERVER_ENC_KEY%"
call :import_sm2 "SM2 client sign" "%SM2_CLIENT_IDX%" "sign" "%SM2_CLIENT_SIGN_KEY%"
call :import_sm2 "SM2 client enc"  "%SM2_CLIENT_IDX%" "enc"  "%SM2_CLIENT_ENC_KEY%"

call :import_rsa "RSA1024 sign" "%RSA1024_IDX%" "sign" "%RSA1024_SIGN_KEY%"
call :import_rsa "RSA1024 enc"  "%RSA1024_IDX%" "enc"  "%RSA1024_ENC_KEY%"
call :import_rsa "RSA2048 sign" "%RSA2048_IDX%" "sign" "%RSA2048_SIGN_KEY%"
call :import_rsa "RSA2048 enc"  "%RSA2048_IDX%" "enc"  "%RSA2048_ENC_KEY%"
call :import_rsa "RSA3072 sign" "%RSA3072_IDX%" "sign" "%RSA3072_SIGN_KEY%"
call :import_rsa "RSA3072 enc"  "%RSA3072_IDX%" "enc"  "%RSA3072_ENC_KEY%"
call :import_rsa "RSA4096 sign" "%RSA4096_IDX%" "sign" "%RSA4096_SIGN_KEY%"
call :import_rsa "RSA4096 enc"  "%RSA4096_IDX%" "enc"  "%RSA4096_ENC_KEY%"

echo.
echo ============================================================
echo  SUMMARY: PASS=!PASS! FAIL=!FAIL!
echo ============================================================

if !FAIL! gtr 0 exit /b 1
exit /b 0

:import_sm2
set "LABEL=%~1"
set "IDX=%~2"
set "TYPE=%~3"
set "KEY=%~4"
call :check_file "%KEY%" || exit /b 0
echo [INFO] !LABEL!: index=!IDX! type=!TYPE! key=!KEY!
REM Delete existing key first (ignore errors, index may be empty)
"%OSSL%" sdf -delsm2key -index "!IDX!" -type "!TYPE!" >nul 2>&1
"%OSSL%" sdf -importsm2key -index "!IDX!" -type "!TYPE!" -inkey "!KEY!" >nul 2>&1
if errorlevel 1 (
    echo [FAIL] !LABEL!
    set /a FAIL+=1
) else (
    echo [OK]   !LABEL!
    set /a PASS+=1
)
exit /b 0

:import_rsa
set "LABEL=%~1"
set "IDX=%~2"
set "TYPE=%~3"
set "KEY=%~4"
call :check_file "%KEY%" || exit /b 0
echo [INFO] !LABEL!: index=!IDX! type=!TYPE! key=!KEY!
REM Delete existing key first (RSA reuses delsm2key, vendor deletes by container index)
"%OSSL%" sdf -delsm2key -index "!IDX!" -type "!TYPE!" >nul 2>&1
"%OSSL%" sdf -importrsakey -index "!IDX!" -type "!TYPE!" -inkey "!KEY!" >nul 2>&1
if errorlevel 1 (
    echo [FAIL] !LABEL!
    set /a FAIL+=1
) else (
    echo [OK]   !LABEL!
    set /a PASS+=1
)
exit /b 0

:check_file
if not exist "%~1" (
    echo [FAIL] missing key file: %~1
    set /a FAIL+=1
    exit /b 1
)
exit /b 0
