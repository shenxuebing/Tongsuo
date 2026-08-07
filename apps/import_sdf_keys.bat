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
set "CERTS=."
set "SM2_CERTS=%CERTS%\sm2"
set "RSA_CERTS=%CERTS%\rsa"

if not exist "%OSSL%" (
    echo [FAIL] cannot find %OSSL%
    exit /b 1
)

if "%SM2_SERVER_IDX%"=="" set "SM2_SERVER_IDX=1"
if "%SM2_CLIENT_IDX%"=="" set "SM2_CLIENT_IDX=2"
if "%SM2_SERVER_SIGN_KEY%"=="" set "SM2_SERVER_SIGN_KEY=%SM2_CERTS%\sm2_server_sign.key"
if "%SM2_SERVER_ENC_KEY%"=="" set "SM2_SERVER_ENC_KEY=%SM2_CERTS%\sm2_server_enc.key"
if "%SM2_CLIENT_SIGN_KEY%"=="" set "SM2_CLIENT_SIGN_KEY=%SM2_CERTS%\sm2_client_sign.key"
if "%SM2_CLIENT_ENC_KEY%"=="" set "SM2_CLIENT_ENC_KEY=%SM2_CERTS%\sm2_client_enc.key"

if "%RSA1024_IDX%"=="" set "RSA1024_IDX=1"
if "%RSA2048_IDX%"=="" set "RSA2048_IDX=2"
if "%RSA3072_IDX%"=="" set "RSA3072_IDX=3"
if "%RSA4096_IDX%"=="" set "RSA4096_IDX=4"

if "%RSA1024_SIGN_KEY%"=="" set "RSA1024_SIGN_KEY=%RSA_CERTS%\rsa1024_sign.key"
if "%RSA1024_ENC_KEY%"=="" set "RSA1024_ENC_KEY=%RSA_CERTS%\rsa1024_enc.key"
if "%RSA2048_SIGN_KEY%"=="" set "RSA2048_SIGN_KEY=%RSA_CERTS%\rsa2048_sign.key"
if "%RSA2048_ENC_KEY%"=="" set "RSA2048_ENC_KEY=%RSA_CERTS%\rsa2048_enc.key"
if "%RSA3072_SIGN_KEY%"=="" set "RSA3072_SIGN_KEY=%RSA_CERTS%\rsa3072_sign.key"
if "%RSA3072_ENC_KEY%"=="" set "RSA3072_ENC_KEY=%RSA_CERTS%\rsa3072_enc.key"
if "%RSA4096_SIGN_KEY%"=="" set "RSA4096_SIGN_KEY=%RSA_CERTS%\rsa4096_sign.key"
if "%RSA4096_ENC_KEY%"=="" set "RSA4096_ENC_KEY=%RSA_CERTS%\rsa4096_enc.key"
if "%IMPORT_GROUP%"=="" set "IMPORT_GROUP=all"

set "DO_SM2="
set "DO_RSA="
if /I "%IMPORT_GROUP%"=="all" (
    set "DO_SM2=1"
    set "DO_RSA=1"
)
if /I "%IMPORT_GROUP%"=="sm2" set "DO_SM2=1"
if /I "%IMPORT_GROUP%"=="rsa" set "DO_RSA=1"
if "%DO_SM2%%DO_RSA%"=="" (
    echo [FAIL] unknown IMPORT_GROUP=%IMPORT_GROUP% ^(expected all, sm2, or rsa^)
    exit /b 1
)

set PASS=0
set FAIL=0

echo ============================================================
echo  Import SDF keys
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo  IMPORT_GROUP=%IMPORT_GROUP%
echo ============================================================

if "%DO_SM2%"=="1" (
    call :import_sm2 "SM2 server sign" "%SM2_SERVER_IDX%" "sign" "%SM2_SERVER_SIGN_KEY%"
    call :import_sm2 "SM2 server enc"  "%SM2_SERVER_IDX%" "enc"  "%SM2_SERVER_ENC_KEY%"
    call :import_sm2 "SM2 client sign" "%SM2_CLIENT_IDX%" "sign" "%SM2_CLIENT_SIGN_KEY%"
    call :import_sm2 "SM2 client enc"  "%SM2_CLIENT_IDX%" "enc"  "%SM2_CLIENT_ENC_KEY%"
)

if "%DO_RSA%"=="1" (
    call :import_rsa "RSA1024 sign" "%RSA1024_IDX%" "sign" "%RSA1024_SIGN_KEY%"
    call :import_rsa "RSA1024 enc"  "%RSA1024_IDX%" "enc"  "%RSA1024_ENC_KEY%"
    call :import_rsa "RSA2048 sign" "%RSA2048_IDX%" "sign" "%RSA2048_SIGN_KEY%"
    call :import_rsa "RSA2048 enc"  "%RSA2048_IDX%" "enc"  "%RSA2048_ENC_KEY%"
    call :import_rsa "RSA3072 sign" "%RSA3072_IDX%" "sign" "%RSA3072_SIGN_KEY%"
    call :import_rsa "RSA3072 enc"  "%RSA3072_IDX%" "enc"  "%RSA3072_ENC_KEY%"
    call :import_rsa "RSA4096 sign" "%RSA4096_IDX%" "sign" "%RSA4096_SIGN_KEY%"
    call :import_rsa "RSA4096 enc"  "%RSA4096_IDX%" "enc"  "%RSA4096_ENC_KEY%"
)

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
call :run "%OSSL%" sdf -delsm2key -index "!IDX!" -type "!TYPE!"
call :run "%OSSL%" sdf -importsm2key -index "!IDX!" -type "!TYPE!" -inkey "!KEY!"
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
REM Delete existing RSA key first (ignore errors, index may be empty)
call :run "%OSSL%" sdf -delrsakey -index "!IDX!" -type "!TYPE!"
call :run "%OSSL%" sdf -importrsakey -index "!IDX!" -type "!TYPE!" -inkey "!KEY!"
if errorlevel 1 (
    echo [FAIL] !LABEL!
    set /a FAIL+=1
) else (
    echo [OK]   !LABEL!
    set /a PASS+=1
)
exit /b 0

:run
echo [CMD] %* 1>&2
%*
exit /b %errorlevel%

:check_file
if not exist "%~1" (
    echo [FAIL] missing key file: %~1
    set /a FAIL+=1
    exit /b 1
)
exit /b 0
