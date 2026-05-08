@echo off
call "D:\Visual Studio 2022\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1
cd /d E:\vs2022workspace\Tongsuo\apps

echo Testing SDF key loading and signing...
echo.

echo [1] Creating test data...
echo "Hello World" > test_data.txt

echo [2] Testing sign key...
.\openssl.exe dgst -sm3 -sign "sdf:key=0;type=sign" -provider sdfprov -provider default -out test_sig.bin test_data.txt
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Sign key works!
) else (
    echo [FAIL] Sign key failed!
)

echo.
echo [3] Testing enc key...
.\openssl.exe dgst -sm3 -sign "sdf:key=0;type=enc" -provider sdfprov -provider default -out test_sig2.bin test_data.txt
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Enc key works!
) else (
    echo [FAIL] Enc key failed!
)

del test_data.txt test_sig.bin test_sig2.bin 2>nul
