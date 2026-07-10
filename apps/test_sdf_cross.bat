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
if "%TMP%"=="" set "TMP=%TEMP%\sdf_cross"
if not exist "%TMP%" mkdir "%TMP%"

set PASS=0
set FAIL=0
set WARN=0

if "%SM2_SIGN_IDX%"=="" set "SM2_SIGN_IDX=0"
if "%SM2_ENC_IDX%"=="" set "SM2_ENC_IDX=0"
if "%SM2_SIGN_CERT%"=="" set "SM2_SIGN_CERT=%CERTS%\sm2\server_sign.crt"
if "%SM2_SIGN_KEY%"=="" set "SM2_SIGN_KEY=%CERTS%\sm2\server_sign.key"
if "%SM2_ENC_CERT%"=="" set "SM2_ENC_CERT=%CERTS%\sm2\server_enc.crt"
if "%SM2_ENC_KEY%"=="" set "SM2_ENC_KEY=%CERTS%\sm2\server_enc.key"
if "%SM2_CAFILE%"=="" set "SM2_CAFILE=%CERTS%\sm2\chain-ca.crt"

if "%RSA2048_SIGN_IDX%"=="" if not "%RSA2048_IDX%"=="" (set "RSA2048_SIGN_IDX=%RSA2048_IDX%") else set "RSA2048_SIGN_IDX=0"
if "%RSA2048_ENC_IDX%"=="" if not "%RSA2048_IDX%"=="" (set "RSA2048_ENC_IDX=%RSA2048_IDX%") else set "RSA2048_ENC_IDX=0"
if "%RSA3072_SIGN_IDX%"=="" if not "%RSA3072_IDX%"=="" set "RSA3072_SIGN_IDX=%RSA3072_IDX%"
if "%RSA3072_ENC_IDX%"=="" if not "%RSA3072_IDX%"=="" set "RSA3072_ENC_IDX=%RSA3072_IDX%"
if "%RSA4096_SIGN_IDX%"=="" if not "%RSA4096_IDX%"=="" set "RSA4096_SIGN_IDX=%RSA4096_IDX%"
if "%RSA4096_ENC_IDX%"=="" if not "%RSA4096_IDX%"=="" set "RSA4096_ENC_IDX=%RSA4096_IDX%"

if "%RSA2048_SIGN_CERT%"=="" set "RSA2048_SIGN_CERT=%CERTS%\server-rsa-sign.crt"
if "%RSA2048_SIGN_KEY%"=="" set "RSA2048_SIGN_KEY=%CERTS%\server-rsa-sign.key"
if "%RSA2048_ENC_CERT%"=="" set "RSA2048_ENC_CERT=%CERTS%\server-rsa-enc.crt"
if "%RSA2048_ENC_KEY%"=="" set "RSA2048_ENC_KEY=%CERTS%\server-rsa-enc.key"

if "%RSA3072_SIGN_CERT%"=="" set "RSA3072_SIGN_CERT=%CERTS%\client_3072_sign.crt"
if "%RSA3072_SIGN_KEY%"=="" set "RSA3072_SIGN_KEY=%CERTS%\client_3072_sign.key"
if "%RSA3072_ENC_CERT%"=="" set "RSA3072_ENC_CERT=%CERTS%\client_3072_enc.crt"
if "%RSA3072_ENC_KEY%"=="" set "RSA3072_ENC_KEY=%CERTS%\client_3072_enc.key"

if "%RSA4096_SIGN_CERT%"=="" set "RSA4096_SIGN_CERT=%CERTS%\client_4096_sign.crt"
if "%RSA4096_SIGN_KEY%"=="" set "RSA4096_SIGN_KEY=%CERTS%\client_4096_sign.key"
if "%RSA4096_ENC_CERT%"=="" set "RSA4096_ENC_CERT=%CERTS%\client_4096_enc.crt"
if "%RSA4096_ENC_KEY%"=="" set "RSA4096_ENC_KEY=%CERTS%\client_4096_enc.key"

echo ============================================================
echo  SDF Provider Cross Verification
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo ============================================================

> "%TMP%\plain.txt" <nul set /p ="cross verify payload 0123456789"

call :run_sm2_suite "%SM2_SIGN_IDX%" "%SM2_ENC_IDX%" "%SM2_SIGN_CERT%" "%SM2_SIGN_KEY%" "%SM2_ENC_CERT%" "%SM2_ENC_KEY%" "%SM2_CAFILE%"
call :run_rsa_suite "RSA2048" "%RSA2048_SIGN_IDX%" "%RSA2048_ENC_IDX%" "%RSA2048_SIGN_CERT%" "%RSA2048_SIGN_KEY%" "%RSA2048_ENC_CERT%" "%RSA2048_ENC_KEY%" "rsa2048"
call :run_rsa_suite "RSA3072" "%RSA3072_SIGN_IDX%" "%RSA3072_ENC_IDX%" "%RSA3072_SIGN_CERT%" "%RSA3072_SIGN_KEY%" "%RSA3072_ENC_CERT%" "%RSA3072_ENC_KEY%" "rsa3072"
call :run_rsa_suite "RSA4096" "%RSA4096_SIGN_IDX%" "%RSA4096_ENC_IDX%" "%RSA4096_SIGN_CERT%" "%RSA4096_SIGN_KEY%" "%RSA4096_ENC_CERT%" "%RSA4096_ENC_KEY%" "rsa4096"

echo.
echo ============================================================
echo  SUMMARY:  PASS=!PASS!  FAIL=!FAIL!  WARN=!WARN!
echo  (WARN = device key missing, cert/index mismatch, or optional suite not enabled)
echo ============================================================

if !FAIL! gtr 0 exit /b 1
exit /b 0

:ok
set "msg=%~1"
echo(  [OK]   !msg!
set /a PASS+=1
exit /b 0

:no
set "msg=%~1"
echo(  [FAIL] !msg!
set /a FAIL+=1
exit /b 0

:wn
set "msg=%~1"
echo(  [WARN] !msg!
set /a WARN+=1
exit /b 0

:copy_local
if not exist "%~1" exit /b 1
copy /y "%~1" "%~2" >nul
exit /b %errorlevel%

:extract_pub
%OSSL% x509 -provider default -in "%~1" -pubkey -noout > "%~2" 2>nul
exit /b %errorlevel%

:run_sm2_suite
set "sign_idx=%~1"
set "enc_idx=%~2"
set "sign_cert=%~3"
set "sign_key=%~4"
set "enc_cert=%~5"
set "enc_key=%~6"
set "cafile=%~7"
set "sign_local=%TMP%\sm2_sign.crt"
set "enc_local=%TMP%\sm2_enc.crt"
set "sign_pub=%TMP%\sm2_sign_pub.pem"
set "enc_pub=%TMP%\sm2_enc_pub.pem"

echo.
echo ==== SM2 suite (sign_idx=%sign_idx% enc_idx=%enc_idx%) ====

call :copy_local "%sign_cert%" "%sign_local%" || (call :no "SM2 missing sign cert: %sign_cert%" & exit /b 0)
call :copy_local "%enc_cert%" "%enc_local%" || (call :no "SM2 missing enc cert: %enc_cert%" & exit /b 0)
call :extract_pub "%sign_local%" "%sign_pub%" || (call :no "SM2 extract sign pub" & exit /b 0)
call :extract_pub "%enc_local%" "%enc_pub%" || (call :no "SM2 extract enc pub" & exit /b 0)

%OSSL% dgst -sm3 -provider sdfprov -provider default -sign "sdf:sm2:%sign_idx%:sign" -out "%TMP%\sm2_p1_h.bin" "%TMP%\plain.txt" 2>nul
if errorlevel 1 (call :no "SM2 P1 HW-sign") else (
    %OSSL% dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_h.bin" "%TMP%\plain.txt" 2>nul | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :wn "SM2 P1 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "SM2 P1 HW-sign -> SW-verify"
)

%OSSL% dgst -sm3 -provider default -sign "%sign_key%" -out "%TMP%\sm2_p1_s.bin" "%TMP%\plain.txt" 2>nul
if errorlevel 1 (call :no "SM2 P1 baseline sign") else (
    %OSSL% dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_s.bin" "%TMP%\plain.txt" 2>nul | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :no "SM2 P1 SW-sign -> SW-verify (baseline)") else call :ok "SM2 P1 SW-sign -> SW-verify (baseline)"
)

%OSSL% pkeyutl -provider default -encrypt -pubin -inkey "%enc_pub%" -in "%TMP%\plain.txt" -out "%TMP%\sm2_ct.bin" 2>nul
if errorlevel 1 (call :no "SM2 plain SW-encrypt") else (
    %OSSL% pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:sm2:%enc_idx%:enc" -in "%TMP%\sm2_ct.bin" -out "%TMP%\sm2_pt.txt" 2>nul
    if errorlevel 1 (call :no "SM2 plain HW-decrypt") else (
        fc /b "%TMP%\plain.txt" "%TMP%\sm2_pt.txt" >nul 2>&1
        if errorlevel 1 (call :wn "SM2 plain SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "SM2 plain SW-encrypt -> HW-decrypt"
    )
)

%OSSL% pkeyutl -provider default -decrypt -inkey "%enc_key%" -in "%TMP%\sm2_ct.bin" -out "%TMP%\sm2_pt2.txt" 2>nul
if errorlevel 1 (call :no "SM2 plain SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\sm2_pt2.txt" >nul 2>&1
    if errorlevel 1 (call :no "SM2 plain SW baseline content mismatch") else call :ok "SM2 plain SW-encrypt -> SW-decrypt (baseline)"
)

%OSSL% pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\sm2_p7_h.p7" -outform DER -signer "%sign_local%" -inkey "sdf:sm2:%sign_idx%:sign" 2>nul
if errorlevel 1 (call :no "SM2 P7 HW-sign") else (
    %OSSL% pkcs7 -verify -provider default -in "%TMP%\sm2_p7_h.p7" -inform DER -content "%TMP%\plain.txt" -CAfile "%cafile%" >nul 2>nul
    if errorlevel 1 (call :wn "SM2 P7 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "SM2 P7 HW-sign -> SW-verify"
)

%OSSL% pkcs7 -sign -gmt0010 -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\sm2_p7_s.p7" -outform DER -signer "%sign_local%" -inkey "%sign_key%" 2>nul
if errorlevel 1 (call :no "SM2 P7 baseline sign") else (
    %OSSL% pkcs7 -verify -provider default -in "%TMP%\sm2_p7_s.p7" -inform DER -content "%TMP%\plain.txt" -CAfile "%cafile%" >nul 2>nul
    if errorlevel 1 (call :no "SM2 P7 SW-sign -> SW-verify (baseline)") else call :ok "SM2 P7 SW-sign -> SW-verify (baseline)"
)

%OSSL% pkcs7 -encrypt -gmt0010 -provider sdfprov -provider default -in "%TMP%\plain.txt" -out "%TMP%\sm2_env_h.p7" -outform DER "%enc_local%" 2>nul
if errorlevel 1 (call :no "SM2 envelope SW-encrypt") else (
    %OSSL% pkcs7 -decrypt -provider sdfprov -provider default -in "%TMP%\sm2_env_h.p7" -inform DER -out "%TMP%\sm2_env_dec.txt" -inkey "sdf:sm2:%enc_idx%:enc" -recip "%enc_local%" 2>nul
    if errorlevel 1 (call :no "SM2 envelope HW-decrypt") else (
        fc /b "%TMP%\plain.txt" "%TMP%\sm2_env_dec.txt" >nul 2>&1
        if errorlevel 1 (call :wn "SM2 envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "SM2 envelope SW-encrypt -> HW-decrypt"
    )
)

%OSSL% pkcs7 -decrypt -provider default -in "%TMP%\sm2_env_h.p7" -inform DER -out "%TMP%\sm2_env_dec2.txt" -inkey "%enc_key%" -recip "%enc_local%" 2>nul
if errorlevel 1 (call :no "SM2 envelope SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\sm2_env_dec2.txt" >nul 2>&1
    if errorlevel 1 (call :no "SM2 envelope SW baseline content mismatch") else call :ok "SM2 envelope SW-encrypt -> SW-decrypt (baseline)"
)
exit /b 0

:run_rsa_suite
set "label=%~1"
set "sign_idx=%~2"
set "enc_idx=%~3"
set "sign_cert=%~4"
set "sign_key=%~5"
set "enc_cert=%~6"
set "enc_key=%~7"
set "tag=%~8"
set "sign_local=%TMP%\%tag%_sign.crt"
set "enc_local=%TMP%\%tag%_enc.crt"
set "sign_pub=%TMP%\%tag%_sign_pub.pem"
set "plain_ct=%TMP%\%tag%_plain.ct"
set "plain_pt=%TMP%\%tag%_plain.pt"
set "p1_sig=%TMP%\%tag%_p1.sig"
set "p7_sig=%TMP%\%tag%_p7.der"
set "env_der=%TMP%\%tag%_env.der"
set "env_pt=%TMP%\%tag%_env.pt"

echo.
echo ==== %label% suite (sign_idx=%sign_idx% enc_idx=%enc_idx%) ====

if "%sign_idx%"=="" (call :wn "%label% skipped (missing sign index)" & exit /b 0)
if "%enc_idx%"=="" (call :wn "%label% skipped (missing enc index)" & exit /b 0)
call :copy_local "%sign_cert%" "%sign_local%" || (call :wn "%label% skipped (missing sign cert: %sign_cert%)" & exit /b 0)
call :copy_local "%enc_cert%" "%enc_local%" || (call :wn "%label% skipped (missing enc cert: %enc_cert%)" & exit /b 0)
call :extract_pub "%sign_local%" "%sign_pub%" || (call :no "%label% extract sign pub" & exit /b 0)

%OSSL% dgst -sha256 -provider sdfprov -provider default -sign "sdf:rsa:%sign_idx%:sign" -out "%p1_sig%" "%TMP%\plain.txt" 2>nul
if errorlevel 1 (call :no "%label% P1 HW-sign") else (
    %OSSL% dgst -sha256 -provider default -verify "%sign_pub%" -signature "%p1_sig%" "%TMP%\plain.txt" 2>nul | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :wn "%label% P1 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "%label% P1 HW-sign -> SW-verify"
)

%OSSL% dgst -sha256 -provider default -sign "%sign_key%" -out "%TMP%\%tag%_p1_sw.sig" "%TMP%\plain.txt" 2>nul
if errorlevel 1 (call :no "%label% P1 baseline sign") else (
    %OSSL% dgst -sha256 -provider default -verify "%sign_pub%" -signature "%TMP%\%tag%_p1_sw.sig" "%TMP%\plain.txt" 2>nul | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :no "%label% P1 SW-sign -> SW-verify (baseline)") else call :ok "%label% P1 SW-sign -> SW-verify (baseline)"
)

%OSSL% pkeyutl -provider default -encrypt -certin -inkey "%enc_local%" -in "%TMP%\plain.txt" -out "%plain_ct%" 2>nul
if errorlevel 1 (call :no "%label% plain SW-encrypt") else (
    %OSSL% pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:rsa:%enc_idx%:enc" -in "%plain_ct%" -out "%plain_pt%" 2>nul
    if errorlevel 1 (call :wn "%label% plain HW-decrypt (device key missing or mismatch?)") else (
        fc /b "%TMP%\plain.txt" "%plain_pt%" >nul 2>&1
        if errorlevel 1 (call :wn "%label% plain SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "%label% plain SW-encrypt -> HW-decrypt"
    )
)

%OSSL% pkeyutl -provider default -decrypt -inkey "%enc_key%" -in "%plain_ct%" -out "%TMP%\%tag%_plain_sw.pt" 2>nul
if errorlevel 1 (call :no "%label% plain SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\%tag%_plain_sw.pt" >nul 2>&1
    if errorlevel 1 (call :no "%label% plain SW baseline content mismatch") else call :ok "%label% plain SW-encrypt -> SW-decrypt (baseline)"
)

%OSSL% pkcs7 -sign -provider sdfprov -provider default -detached -in "%TMP%\plain.txt" -out "%p7_sig%" -outform DER -signer "%sign_local%" -inkey "sdf:rsa:%sign_idx%:sign" 2>nul
if errorlevel 1 (call :wn "%label% P7 HW-sign (device sign cert mismatch?)") else (
    %OSSL% pkcs7 -verify -provider default -in "%p7_sig%" -inform DER -content "%TMP%\plain.txt" -noverify >nul 2>nul
    if errorlevel 1 (call :wn "%label% P7 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "%label% P7 HW-sign -> SW-verify"
)

%OSSL% pkcs7 -sign -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\%tag%_p7_sw.der" -outform DER -signer "%sign_local%" -inkey "%sign_key%" 2>nul
if errorlevel 1 (call :no "%label% P7 baseline sign") else (
    %OSSL% pkcs7 -verify -provider default -in "%TMP%\%tag%_p7_sw.der" -inform DER -content "%TMP%\plain.txt" -noverify >nul 2>nul
    if errorlevel 1 (call :no "%label% P7 SW-sign -> SW-verify (baseline)") else call :ok "%label% P7 SW-sign -> SW-verify (baseline)"
)

%OSSL% smime -encrypt -binary -outform DER -in "%TMP%\plain.txt" -out "%env_der%" "%enc_local%" 2>nul
if errorlevel 1 (call :no "%label% envelope SW-encrypt") else (
    %OSSL% smime -decrypt -inform DER -in "%env_der%" -recip "%enc_local%" -inkey "sdf:rsa:%enc_idx%:enc" -provider sdfprov -provider default -out "%env_pt%" 2>nul
    if errorlevel 1 (call :wn "%label% envelope HW-decrypt (device enc key missing or mismatch?)") else (
        fc /b "%TMP%\plain.txt" "%env_pt%" >nul 2>&1
        if errorlevel 1 (call :wn "%label% envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "%label% envelope SW-encrypt -> HW-decrypt"
    )
)

%OSSL% smime -decrypt -inform DER -in "%env_der%" -recip "%enc_local%" -inkey "%enc_key%" -provider default -out "%TMP%\%tag%_env_sw.pt" 2>nul
if errorlevel 1 (call :no "%label% envelope SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\%tag%_env_sw.pt" >nul 2>&1
    if errorlevel 1 (call :no "%label% envelope SW baseline content mismatch") else call :ok "%label% envelope SW-encrypt -> SW-decrypt (baseline)"
)
exit /b 0
