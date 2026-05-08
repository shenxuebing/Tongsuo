@echo off
cd /d E:\vs2022workspace\Tongsuo\apps
echo === Test 1: List Providers ===
openssl.exe list -providers -provider sdfprov 2>&1
echo.
echo === Test 2: Test STORE URI key loading ===
echo Testing sdf:key=0;type=sign key load...
openssl.exe pkey -in "sdf:key=0;type=sign" -provider sdfprov -provider default -text -noout 2>&1
echo.
echo === Test 3: Export public key via STORE ===
openssl.exe pkey -in "sdf:key=0;type=enc" -provider sdfprov -provider default -text -noout 2>&1
echo.
echo === Done ===
