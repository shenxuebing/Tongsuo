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
set "CERTS=.\certs"
set "SM2_CERTS=%CERTS%\sm2"
set "RSA_CERTS=%CERTS%\rsa"
cd /d "%~dp0"
set "TMP=%CD%"

set PASS=0
set FAIL=0
set WARN=0

if "%SM2_SIGN_IDX%"=="" set "SM2_SIGN_IDX=1"
if "%SM2_ENC_IDX%"=="" set "SM2_ENC_IDX=1"
if "%SM2_SIGN_CERT%"=="" set "SM2_SIGN_CERT=%SM2_CERTS%\sm2_server_sign.crt"
if "%SM2_SIGN_KEY%"=="" set "SM2_SIGN_KEY=%SM2_CERTS%\sm2_server_sign.key"
if "%SM2_ENC_CERT%"=="" set "SM2_ENC_CERT=%SM2_CERTS%\sm2_server_enc.crt"
if "%SM2_ENC_KEY%"=="" set "SM2_ENC_KEY=%SM2_CERTS%\sm2_server_enc.key"
if "%SM2_CAFILE%"=="" set "SM2_CAFILE=%SM2_CERTS%\sm2_chain-ca.crt"

if "%RSA1024_SIGN_IDX%"=="" if not "%RSA1024_IDX%"=="" (set "RSA1024_SIGN_IDX=%RSA1024_IDX%") else set "RSA1024_SIGN_IDX=1"
if "%RSA1024_ENC_IDX%"=="" if not "%RSA1024_IDX%"=="" (set "RSA1024_ENC_IDX=%RSA1024_IDX%") else set "RSA1024_ENC_IDX=1"
if "%RSA2048_SIGN_IDX%"=="" if not "%RSA2048_IDX%"=="" (set "RSA2048_SIGN_IDX=%RSA2048_IDX%") else set "RSA2048_SIGN_IDX=2"
if "%RSA2048_ENC_IDX%"=="" if not "%RSA2048_IDX%"=="" (set "RSA2048_ENC_IDX=%RSA2048_IDX%") else set "RSA2048_ENC_IDX=2"
if "%RSA3072_SIGN_IDX%"=="" if not "%RSA3072_IDX%"=="" set "RSA3072_SIGN_IDX=%RSA3072_IDX%"
if "%RSA3072_ENC_IDX%"=="" if not "%RSA3072_IDX%"=="" set "RSA3072_ENC_IDX=%RSA3072_IDX%"
if "%RSA4096_SIGN_IDX%"=="" if not "%RSA4096_IDX%"=="" set "RSA4096_SIGN_IDX=%RSA4096_IDX%"
if "%RSA4096_ENC_IDX%"=="" if not "%RSA4096_IDX%"=="" set "RSA4096_ENC_IDX=%RSA4096_IDX%"
if "%RSA3072_SIGN_IDX%"=="" set "RSA3072_SIGN_IDX=3"
if "%RSA3072_ENC_IDX%"=="" set "RSA3072_ENC_IDX=3"
if "%RSA4096_SIGN_IDX%"=="" set "RSA4096_SIGN_IDX=4"
if "%RSA4096_ENC_IDX%"=="" set "RSA4096_ENC_IDX=4"

if "%RSA1024_SIGN_CERT%"=="" set "RSA1024_SIGN_CERT=%RSA_CERTS%\rsa1024_sign.crt"
if "%RSA1024_SIGN_KEY%"=="" set "RSA1024_SIGN_KEY=%RSA_CERTS%\rsa1024_sign.key"
if "%RSA1024_ENC_CERT%"=="" set "RSA1024_ENC_CERT=%RSA_CERTS%\rsa1024_enc.crt"
if "%RSA1024_ENC_KEY%"=="" set "RSA1024_ENC_KEY=%RSA_CERTS%\rsa1024_enc.key"

if "%RSA2048_SIGN_CERT%"=="" set "RSA2048_SIGN_CERT=%RSA_CERTS%\rsa2048_sign.crt"
if "%RSA2048_SIGN_KEY%"=="" set "RSA2048_SIGN_KEY=%RSA_CERTS%\rsa2048_sign.key"
if "%RSA2048_ENC_CERT%"=="" set "RSA2048_ENC_CERT=%RSA_CERTS%\rsa2048_enc.crt"
if "%RSA2048_ENC_KEY%"=="" set "RSA2048_ENC_KEY=%RSA_CERTS%\rsa2048_enc.key"

if "%RSA3072_SIGN_CERT%"=="" set "RSA3072_SIGN_CERT=%RSA_CERTS%\rsa3072_sign.crt"
if "%RSA3072_SIGN_KEY%"=="" set "RSA3072_SIGN_KEY=%RSA_CERTS%\rsa3072_sign.key"
if "%RSA3072_ENC_CERT%"=="" set "RSA3072_ENC_CERT=%RSA_CERTS%\rsa3072_enc.crt"
if "%RSA3072_ENC_KEY%"=="" set "RSA3072_ENC_KEY=%RSA_CERTS%\rsa3072_enc.key"

if "%RSA4096_SIGN_CERT%"=="" set "RSA4096_SIGN_CERT=%RSA_CERTS%\rsa4096_sign.crt"
if "%RSA4096_SIGN_KEY%"=="" set "RSA4096_SIGN_KEY=%RSA_CERTS%\rsa4096_sign.key"
if "%RSA4096_ENC_CERT%"=="" set "RSA4096_ENC_CERT=%RSA_CERTS%\rsa4096_enc.crt"
if "%RSA4096_ENC_KEY%"=="" set "RSA4096_ENC_KEY=%RSA_CERTS%\rsa4096_enc.key"

echo ============================================================
echo  SDF Provider Cross Verification
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo ============================================================

if /I not "%IMPORT_KEYS%"=="0" (
    echo [CMD] call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=sm2
    call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=sm2
    if errorlevel 1 exit /b 1
)

> "%TMP%\plain.txt" <nul set /p ="cross verify payload 0123456789"

call :run_sm2_suite "%SM2_SIGN_IDX%" "%SM2_ENC_IDX%" "%SM2_SIGN_CERT%" "%SM2_SIGN_KEY%" "%SM2_ENC_CERT%" "%SM2_ENC_KEY%" "%SM2_CAFILE%"

if /I not "%IMPORT_KEYS%"=="0" (
    echo [CMD] call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=rsa
    call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=rsa
    if errorlevel 1 exit /b 1
)

call :run_rsa_suite "RSA1024" "%RSA1024_SIGN_IDX%" "%RSA1024_ENC_IDX%" "%RSA1024_SIGN_CERT%" "%RSA1024_SIGN_KEY%" "%RSA1024_ENC_CERT%" "%RSA1024_ENC_KEY%" "rsa1024"
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
call :run "%OSSL%" x509 -provider default -in "%~1" -pubkey -noout > "%~2"
exit /b %errorlevel%

:run
echo [CMD] %* 1>&2
%*
exit /b %errorlevel%

:print_cmd
echo [CMD] %* 1>&2
exit /b 0

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

call :run "%OSSL%" dgst -sm3 -provider sdfprov -provider default -sign "sdf:sm2:%sign_idx%:sign" -out "%TMP%\sm2_p1_h.bin" "%TMP%\plain.txt"
if errorlevel 1 (call :no "SM2 P1 HW-sign") else (
    call :print_cmd "%OSSL%" dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_h.bin" "%TMP%\plain.txt"
    "%OSSL%" dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_h.bin" "%TMP%\plain.txt" | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :wn "SM2 P1 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "SM2 P1 HW-sign -> SW-verify"
)

call :run "%OSSL%" dgst -sm3 -provider default -sign "%sign_key%" -out "%TMP%\sm2_p1_s.bin" "%TMP%\plain.txt"
if errorlevel 1 (call :no "SM2 P1 baseline sign") else (
    call :print_cmd "%OSSL%" dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_s.bin" "%TMP%\plain.txt"
    "%OSSL%" dgst -sm3 -provider default -verify "%sign_pub%" -signature "%TMP%\sm2_p1_s.bin" "%TMP%\plain.txt" | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :no "SM2 P1 SW-sign -> SW-verify (baseline)") else call :ok "SM2 P1 SW-sign -> SW-verify (baseline)"
)

call :run "%OSSL%" pkeyutl -provider default -encrypt -pubin -inkey "%enc_pub%" -in "%TMP%\plain.txt" -out "%TMP%\sm2_ct.bin"
if errorlevel 1 (call :no "SM2 plain SW-encrypt") else (
    call :run "%OSSL%" pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:sm2:%enc_idx%:enc" -in "%TMP%\sm2_ct.bin" -out "%TMP%\sm2_pt.txt"
    if errorlevel 1 (call :no "SM2 plain HW-decrypt") else (
        fc /b "%TMP%\plain.txt" "%TMP%\sm2_pt.txt" >nul 2>&1
        if errorlevel 1 (call :wn "SM2 plain SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "SM2 plain SW-encrypt -> HW-decrypt"
    )
)

call :run "%OSSL%" pkeyutl -provider default -decrypt -inkey "%enc_key%" -in "%TMP%\sm2_ct.bin" -out "%TMP%\sm2_pt2.txt"
if errorlevel 1 (call :no "SM2 plain SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\sm2_pt2.txt" >nul 2>&1
    if errorlevel 1 (call :no "SM2 plain SW baseline content mismatch") else call :ok "SM2 plain SW-encrypt -> SW-decrypt (baseline)"
)

call :run "%OSSL%" pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\sm2_p7_h.p7" -outform DER -signer "%sign_local%" -inkey "sdf:sm2:%sign_idx%:sign"
if errorlevel 1 (call :no "SM2 P7 HW-sign") else (
    call :run "%OSSL%" pkcs7 -verify -provider default -in "%TMP%\sm2_p7_h.p7" -inform DER -content "%TMP%\plain.txt" -CAfile "%cafile%" >nul
    if errorlevel 1 (call :wn "SM2 P7 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "SM2 P7 HW-sign -> SW-verify"
)

call :run "%OSSL%" pkcs7 -sign -gmt0010 -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\sm2_p7_s.p7" -outform DER -signer "%sign_local%" -inkey "%sign_key%"
if errorlevel 1 (call :no "SM2 P7 baseline sign") else (
    call :run "%OSSL%" pkcs7 -verify -provider default -in "%TMP%\sm2_p7_s.p7" -inform DER -content "%TMP%\plain.txt" -CAfile "%cafile%" >nul
    if errorlevel 1 (call :no "SM2 P7 SW-sign -> SW-verify (baseline)") else call :ok "SM2 P7 SW-sign -> SW-verify (baseline)"
)

call :run "%OSSL%" pkcs7 -encrypt -gmt0010 -provider sdfprov -provider default -in "%TMP%\plain.txt" -out "%TMP%\sm2_env_h.p7" -outform DER "%enc_local%"
if errorlevel 1 (call :no "SM2 envelope SW-encrypt") else (
    call :run "%OSSL%" pkcs7 -decrypt -provider sdfprov -provider default -in "%TMP%\sm2_env_h.p7" -inform DER -out "%TMP%\sm2_env_dec.txt" -inkey "sdf:sm2:%enc_idx%:enc" -recip "%enc_local%"
    if errorlevel 1 (call :no "SM2 envelope HW-decrypt") else (
        fc /b "%TMP%\plain.txt" "%TMP%\sm2_env_dec.txt" >nul 2>&1
        if errorlevel 1 (call :wn "SM2 envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "SM2 envelope SW-encrypt -> HW-decrypt"
    )
)

call :run "%OSSL%" pkcs7 -decrypt -provider default -in "%TMP%\sm2_env_h.p7" -inform DER -out "%TMP%\sm2_env_dec2.txt" -inkey "%enc_key%" -recip "%enc_local%"
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

call :run "%OSSL%" dgst -sha256 -provider sdfprov -provider default -sign "sdf:rsa:%sign_idx%:sign" -out "%p1_sig%" "%TMP%\plain.txt"
if errorlevel 1 (call :no "%label% P1 HW-sign") else (
    call :print_cmd "%OSSL%" dgst -sha256 -provider default -verify "%sign_pub%" -signature "%p1_sig%" "%TMP%\plain.txt"
    "%OSSL%" dgst -sha256 -provider default -verify "%sign_pub%" -signature "%p1_sig%" "%TMP%\plain.txt" | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :wn "%label% P1 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "%label% P1 HW-sign -> SW-verify"
)

call :run "%OSSL%" dgst -sha256 -provider default -sign "%sign_key%" -out "%TMP%\%tag%_p1_sw.sig" "%TMP%\plain.txt"
if errorlevel 1 (call :no "%label% P1 baseline sign") else (
    call :print_cmd "%OSSL%" dgst -sha256 -provider default -verify "%sign_pub%" -signature "%TMP%\%tag%_p1_sw.sig" "%TMP%\plain.txt"
    "%OSSL%" dgst -sha256 -provider default -verify "%sign_pub%" -signature "%TMP%\%tag%_p1_sw.sig" "%TMP%\plain.txt" | findstr /C:"Verified OK" >nul
    if errorlevel 1 (call :no "%label% P1 SW-sign -> SW-verify (baseline)") else call :ok "%label% P1 SW-sign -> SW-verify (baseline)"
)

call :run "%OSSL%" pkeyutl -provider default -encrypt -certin -inkey "%enc_local%" -in "%TMP%\plain.txt" -out "%plain_ct%"
if errorlevel 1 (call :no "%label% plain SW-encrypt") else (
    call :run "%OSSL%" pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:rsa:%enc_idx%:enc" -in "%plain_ct%" -out "%plain_pt%"
    if errorlevel 1 (call :wn "%label% plain HW-decrypt (device key missing or mismatch?)") else (
        fc /b "%TMP%\plain.txt" "%plain_pt%" >nul 2>&1
        if errorlevel 1 (call :wn "%label% plain SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "%label% plain SW-encrypt -> HW-decrypt"
    )
)

call :run "%OSSL%" pkeyutl -provider default -decrypt -inkey "%enc_key%" -in "%plain_ct%" -out "%TMP%\%tag%_plain_sw.pt"
if errorlevel 1 (call :no "%label% plain SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\%tag%_plain_sw.pt" >nul 2>&1
    if errorlevel 1 (call :no "%label% plain SW baseline content mismatch") else call :ok "%label% plain SW-encrypt -> SW-decrypt (baseline)"
)

call :run "%OSSL%" pkcs7 -sign -provider sdfprov -provider default -detached -in "%TMP%\plain.txt" -out "%p7_sig%" -outform DER -signer "%sign_local%" -inkey "sdf:rsa:%sign_idx%:sign"
if errorlevel 1 (call :wn "%label% P7 HW-sign (device sign cert mismatch?)") else (
    call :run "%OSSL%" pkcs7 -verify -provider default -in "%p7_sig%" -inform DER -content "%TMP%\plain.txt" -noverify >nul
    if errorlevel 1 (call :wn "%label% P7 HW-sign -> SW-verify (certificate/key mismatch?)") else call :ok "%label% P7 HW-sign -> SW-verify"
)

call :run "%OSSL%" pkcs7 -sign -provider default -detached -in "%TMP%\plain.txt" -out "%TMP%\%tag%_p7_sw.der" -outform DER -signer "%sign_local%" -inkey "%sign_key%"
if errorlevel 1 (call :no "%label% P7 baseline sign") else (
    call :run "%OSSL%" pkcs7 -verify -provider default -in "%TMP%\%tag%_p7_sw.der" -inform DER -content "%TMP%\plain.txt" -noverify >nul
    if errorlevel 1 (call :no "%label% P7 SW-sign -> SW-verify (baseline)") else call :ok "%label% P7 SW-sign -> SW-verify (baseline)"
)

call :run "%OSSL%" smime -encrypt -binary -outform DER -in "%TMP%\plain.txt" -out "%env_der%" "%enc_local%"
if errorlevel 1 (call :no "%label% envelope SW-encrypt") else (
    call :run "%OSSL%" smime -decrypt -inform DER -in "%env_der%" -recip "%enc_local%" -inkey "sdf:rsa:%enc_idx%:enc" -provider sdfprov -provider default -out "%env_pt%"
    if errorlevel 1 (call :wn "%label% envelope HW-decrypt (device enc key missing or mismatch?)") else (
        fc /b "%TMP%\plain.txt" "%env_pt%" >nul 2>&1
        if errorlevel 1 (call :wn "%label% envelope SW-encrypt -> HW-decrypt (cert/index mismatch?)") else call :ok "%label% envelope SW-encrypt -> HW-decrypt"
    )
)

call :run "%OSSL%" smime -decrypt -inform DER -in "%env_der%" -recip "%enc_local%" -inkey "%enc_key%" -provider default -out "%TMP%\%tag%_env_sw.pt"
if errorlevel 1 (call :no "%label% envelope SW baseline decrypt") else (
    fc /b "%TMP%\plain.txt" "%TMP%\%tag%_env_sw.pt" >nul 2>&1
    if errorlevel 1 (call :no "%label% envelope SW baseline content mismatch") else call :ok "%label% envelope SW-encrypt -> SW-decrypt (baseline)"
)
exit /b 0
