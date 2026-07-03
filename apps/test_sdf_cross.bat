@echo off
REM ============================================================
REM SDF Provider Full Cross Verification
REM
REM Matrix:
REM   Algo:  SM2 / RSA
REM   Op:    P1 sign(dgst) / P7 sign(pkcs7) / envelope(pkcs7) / plain(pkeyutl)
REM   Key:   Hardware(SDF URI) / Software(PEM)
REM   Cross: HW-sign->SW-verify, SW-encrypt->HW-decrypt, etc.
REM
REM Usage:  run in apps directory:  test_sdf_cross.bat
REM PreReq: OPENSSL_CONF points to openssl.cnf with sdf_use_loadmodule=1
REM ============================================================

setlocal enabledelayedexpansion
set OPENSSL_CONF=%~dp0openssl.cnf
set OSSL=%~dp0openssl.exe
set CERTS=..\test\certs
set TMP=%TEMP%\sdf_cross
if not exist %TMP% mkdir %TMP%

set PASS=0
set FAIL=0
set WARN=0

echo ============================================================
echo  SDF Provider Cross Verification
echo  OPENSSL_CONF=%OPENSSL_CONF%
echo ============================================================
echo.

REM Extract public keys from certs (for dgst verify / pkeyutl -pubin)
%OSSL% x509 -in %CERTS%\sm2\server_sign.crt -pubkey -noout > %TMP%\sm2_sign_pub.pem 2>nul
%OSSL% x509 -in %CERTS%\sm2\server_enc.crt  -pubkey -noout > %TMP%\sm2_enc_pub.pem  2>nul
%OSSL% x509 -in %CERTS%\server-rsa-sign.crt -pubkey -noout > %TMP%\rsa_sign_pub.pem 2>nul
%OSSL% x509 -in %CERTS%\server-rsa-enc.crt  -pubkey -noout > %TMP%\rsa_enc_pub.pem  2>nul

REM Common plaintext (no trailing newline to avoid CRLF diff)
<nul set /p =cross verify payload 0123456789> %TMP%\plain.txt

echo ==== Part 1: SM2 P1 sign/verify (dgst) ====
%OSSL% dgst -sm3 -provider sdfprov -provider default -sign "sdf:sm2:0:sign" -out %TMP%\sm2_p1_h.bin %TMP%\plain.txt 2>nul
if !errorlevel! neq 0 ( echo   [FAIL] SM2 P1 HW-sign & set /a FAIL+=1 ) else (
    %OSSL% dgst -sm3 -provider default -verify %TMP%\sm2_sign_pub.pem -signature %TMP%\sm2_p1_h.bin %TMP%\plain.txt 2>nul | findstr /C:"Verified OK" >nul
    if !errorlevel! equ 0 ( echo   [OK]   SM2 P1 HW-sign -^> SW-verify & set /a PASS+=1 ) else ( echo   [FAIL] SM2 P1 HW-sign verify & set /a FAIL+=1 )
)
%OSSL% dgst -sm3 -provider default -sign %CERTS%\sm2\server_sign.key -out %TMP%\sm2_p1_s.bin %TMP%\plain.txt 2>nul
%OSSL% dgst -sm3 -provider default -verify %TMP%\sm2_sign_pub.pem -signature %TMP%\sm2_p1_s.bin %TMP%\plain.txt 2>nul | findstr /C:"Verified OK" >nul
if !errorlevel! equ 0 ( echo   [OK]   SM2 P1 SW-sign -^> SW-verify ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] SM2 P1 SW-sign baseline & set /a FAIL+=1 )
echo.

echo ==== Part 2: RSA P1 sign/verify (dgst) ====
%OSSL% dgst -sha256 -provider sdfprov -provider default -sign "sdf:rsa:0:sign" -out %TMP%\rsa_p1_h.bin %TMP%\plain.txt 2>nul
if !errorlevel! neq 0 ( echo   [FAIL] RSA P1 HW-sign & set /a FAIL+=1 ) else (
    %OSSL% dgst -sha256 -provider default -verify %TMP%\rsa_sign_pub.pem -signature %TMP%\rsa_p1_h.bin %TMP%\plain.txt 2>nul | findstr /C:"Verified OK" >nul
    if !errorlevel! equ 0 ( echo   [OK]   RSA P1 HW-sign -^> SW-verify & set /a PASS+=1 ) else ( echo   [FAIL] RSA P1 HW-sign verify & set /a FAIL+=1 )
)
%OSSL% dgst -sha256 -provider default -sign %CERTS%\server-rsa-sign.key -out %TMP%\rsa_p1_s.bin %TMP%\plain.txt 2>nul
%OSSL% dgst -sha256 -provider default -verify %TMP%\rsa_sign_pub.pem -signature %TMP%\rsa_p1_s.bin %TMP%\plain.txt 2>nul | findstr /C:"Verified OK" >nul
if !errorlevel! equ 0 ( echo   [OK]   RSA P1 SW-sign -^> SW-verify ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] RSA P1 SW-sign baseline & set /a FAIL+=1 )
echo.

echo ==== Part 3: SM2 plain encrypt/decrypt (pkeyutl) ====
%OSSL% pkeyutl -provider default -encrypt -pubin -inkey %TMP%\sm2_enc_pub.pem -in %TMP%\plain.txt -out %TMP%\sm2_ct.bin 2>nul
%OSSL% pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:sm2:0:enc" -in %TMP%\sm2_ct.bin -out %TMP%\sm2_pt.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\sm2_pt.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   SM2 plain SW-encrypt -^> HW-decrypt & set /a PASS+=1 ) else ( echo   [FAIL] SM2 plain HW-decrypt & set /a FAIL+=1 )
%OSSL% pkeyutl -provider default -decrypt -inkey %CERTS%\sm2\server_enc.key -in %TMP%\sm2_ct.bin -out %TMP%\sm2_pt2.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\sm2_pt2.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   SM2 plain SW-encrypt -^> SW-decrypt ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] SM2 plain SW-decrypt baseline & set /a FAIL+=1 )
echo.

echo ==== Part 4: RSA plain encrypt/decrypt (pkeyutl) ====
%OSSL% pkeyutl -provider default -encrypt -pubin -inkey %TMP%\rsa_sign_pub.pem -in %TMP%\plain.txt -out %TMP%\rsa_sign_ct.bin 2>nul
%OSSL% pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:rsa:0:sign" -in %TMP%\rsa_sign_ct.bin -out %TMP%\rsa_sign_pt.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_sign_pt.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA sign SW-encrypt -^> HW-decrypt & set /a PASS+=1 ) else ( echo   [FAIL] RSA sign HW-decrypt & set /a FAIL+=1 )
%OSSL% pkeyutl -provider default -decrypt -inkey %CERTS%\server-rsa-sign.key -in %TMP%\rsa_sign_ct.bin -out %TMP%\rsa_sign_pt2.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_sign_pt2.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA sign SW-encrypt -^> SW-decrypt ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] RSA sign SW-decrypt baseline & set /a FAIL+=1 )
%OSSL% pkeyutl -provider default -encrypt -pubin -inkey %TMP%\rsa_enc_pub.pem -in %TMP%\plain.txt -out %TMP%\rsa_enc_ct.bin 2>nul
%OSSL% pkeyutl -provider sdfprov -provider default -decrypt -inkey "sdf:rsa:0:enc" -in %TMP%\rsa_enc_ct.bin -out %TMP%\rsa_enc_pt.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_enc_pt.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA enc SW-encrypt -^> HW-decrypt & set /a PASS+=1 ) else ( echo   [FAIL] RSA enc HW-decrypt & set /a FAIL+=1 )
%OSSL% pkeyutl -provider default -decrypt -inkey %CERTS%\server-rsa-enc.key -in %TMP%\rsa_enc_ct.bin -out %TMP%\rsa_enc_pt2.txt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_enc_pt2.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA enc SW-encrypt -^> SW-decrypt ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] RSA enc SW-decrypt baseline & set /a FAIL+=1 )
echo.

echo ==== Part 5: SM2 P7 sign/verify (pkcs7 detached + content) ====
%OSSL% pkcs7 -sign -gmt0010 -provider sdfprov -provider default -detached -in %TMP%\plain.txt -out %TMP%\sm2_p7_h.p7 -outform DER -signer %CERTS%\sm2\server_sign.crt -inkey "sdf:sm2:0:sign" 2>nul
%OSSL% pkcs7 -verify -provider default -in %TMP%\sm2_p7_h.p7 -inform DER -content %TMP%\plain.txt -CAfile %CERTS%\sm2\chain-ca.crt >nul 2>nul
if !errorlevel! equ 0 ( echo   [OK]   SM2 P7 HW-sign -^> SW-verify & set /a PASS+=1 ) else ( echo   [FAIL] SM2 P7 HW-sign verify & set /a FAIL+=1 )
%OSSL% pkcs7 -sign -gmt0010 -provider default -detached -in %TMP%\plain.txt -out %TMP%\sm2_p7_s.p7 -outform DER -signer %CERTS%\sm2\server_sign.crt -inkey %CERTS%\sm2\server_sign.key 2>nul
%OSSL% pkcs7 -verify -provider default -in %TMP%\sm2_p7_s.p7 -inform DER -content %TMP%\plain.txt -CAfile %CERTS%\sm2\chain-ca.crt >nul 2>nul
if !errorlevel! equ 0 ( echo   [OK]   SM2 P7 SW-sign -^> SW-verify ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] SM2 P7 SW-sign baseline & set /a FAIL+=1 )
echo.

echo ==== Part 6: RSA P7 sign/verify (pkcs7 detached + content, noverify) ====
REM RSA test certs issuer=Root CA (no CA file), use -noverify to check signature only
%OSSL% pkcs7 -sign -provider sdfprov -provider default -detached -in %TMP%\plain.txt -out %TMP%\rsa_p7_h.p7 -outform DER -signer %CERTS%\server-rsa-sign.crt -inkey "sdf:rsa:0:sign" 2>nul
%OSSL% pkcs7 -verify -provider default -in %TMP%\rsa_p7_h.p7 -inform DER -content %TMP%\plain.txt -noverify >nul 2>nul
if !errorlevel! equ 0 ( echo   [OK]   RSA P7 HW-sign -^> SW-verify & set /a PASS+=1 ) else ( echo   [FAIL] RSA P7 HW-sign verify & set /a FAIL+=1 )
%OSSL% pkcs7 -sign -provider default -detached -in %TMP%\plain.txt -out %TMP%\rsa_p7_s.p7 -outform DER -signer %CERTS%\server-rsa-sign.crt -inkey %CERTS%\server-rsa-sign.key 2>nul
%OSSL% pkcs7 -verify -provider default -in %TMP%\rsa_p7_s.p7 -inform DER -content %TMP%\plain.txt -noverify >nul 2>nul
if !errorlevel! equ 0 ( echo   [OK]   RSA P7 SW-sign -^> SW-verify ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] RSA P7 SW-sign baseline & set /a FAIL+=1 )
echo.

echo ==== Part 7: SM2 digital envelope (pkcs7) ====
%OSSL% pkcs7 -encrypt -gmt0010 -provider sdfprov -provider default -in %TMP%\plain.txt -out %TMP%\sm2_env.p7 -outform DER %CERTS%\sm2\server_enc.crt 2>nul
%OSSL% pkcs7 -decrypt -provider sdfprov -provider default -in %TMP%\sm2_env.p7 -inform DER -out %TMP%\sm2_env_dec.txt -inkey "sdf:sm2:0:enc" -recip %CERTS%\sm2\server_enc.crt 2>nul
fc /b %TMP%\plain.txt %TMP%\sm2_env_dec.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   SM2 envelope SW-encrypt -^> HW-decrypt & set /a PASS+=1 ) else ( echo   [FAIL] SM2 envelope HW-decrypt & set /a FAIL+=1 )
%OSSL% pkcs7 -decrypt -provider default -in %TMP%\sm2_env.p7 -inform DER -out %TMP%\sm2_env_dec2.txt -inkey %CERTS%\sm2\server_enc.key -recip %CERTS%\sm2\server_enc.crt 2>nul
fc /b %TMP%\plain.txt %TMP%\sm2_env_dec2.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   SM2 envelope SW-encrypt -^> SW-decrypt ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] SM2 envelope SW-decrypt baseline & set /a FAIL+=1 )
echo.

echo ==== Part 8: RSA digital envelope (pkcs7) ====
%OSSL% pkcs7 -encrypt -provider sdfprov -provider default -in %TMP%\plain.txt -out %TMP%\rsa_env.p7 -outform DER %CERTS%\server-rsa-enc.crt 2>nul
%OSSL% pkcs7 -decrypt -provider sdfprov -provider default -in %TMP%\rsa_env.p7 -inform DER -out %TMP%\rsa_env_dec.txt -inkey "sdf:rsa:0:enc" -recip %CERTS%\server-rsa-enc.crt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_env_dec.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA envelope SW-encrypt -^> HW-decrypt & set /a PASS+=1 ) else ( echo   [FAIL] RSA envelope HW-decrypt & set /a FAIL+=1 )
%OSSL% pkcs7 -decrypt -provider default -in %TMP%\rsa_env.p7 -inform DER -out %TMP%\rsa_env_dec2.txt -inkey %CERTS%\server-rsa-enc.key -recip %CERTS%\server-rsa-enc.crt 2>nul
fc /b %TMP%\plain.txt %TMP%\rsa_env_dec2.txt >nul 2>&1
if !errorlevel! equ 0 ( echo   [OK]   RSA envelope SW-encrypt -^> SW-decrypt ^(baseline^) & set /a PASS+=1 ) else ( echo   [FAIL] RSA envelope SW-decrypt baseline & set /a FAIL+=1 )
echo.

echo ============================================================
echo  SUMMARY:  PASS=!PASS!  FAIL=!FAIL!  WARN=!WARN!
echo ============================================================
if !FAIL! gtr 0 exit /b 1
endlocal
exit /b 0
