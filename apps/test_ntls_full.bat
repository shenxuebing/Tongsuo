@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

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

if "%OPENSSL_CONF%"=="" set "OPENSSL_CONF=%CD%\openssl.cnf"
set PASS=0
set FAIL=0
set NUM=0
set "OUTDIR=%CD%"
if "%CERTS%"=="" set "CERTS=..\test\certs\sm2"
if "%CAFILE%"=="" set "CAFILE=%CERTS%\chain-ca.crt"
if "%SERVER_CERT_PROFILE%"=="" set "SERVER_CERT_PROFILE=sm2"
if "%CLIENT_CERT_PROFILE%"=="" set "CLIENT_CERT_PROFILE=sm2"

if "%SERVER_SIGN_CERT%"=="" set "SERVER_SIGN_CERT=%CERTS%\server_sign.crt"
if "%SERVER_ENC_CERT%"=="" set "SERVER_ENC_CERT=%CERTS%\server_enc.crt"
if "%SERVER_SIGN_KEY%"=="" set "SERVER_SIGN_KEY=%CERTS%\server_sign.key"
if "%SERVER_ENC_KEY%"=="" set "SERVER_ENC_KEY=%CERTS%\server_enc.key"

if "%CLIENT_SIGN_CERT%"=="" set "CLIENT_SIGN_CERT=%CERTS%\client_sign.crt"
if "%CLIENT_ENC_CERT%"=="" set "CLIENT_ENC_CERT=%CERTS%\client_enc.crt"
if "%CLIENT_SIGN_KEY%"=="" set "CLIENT_SIGN_KEY=%CERTS%\client_sign.key"
if "%CLIENT_ENC_KEY%"=="" set "CLIENT_ENC_KEY=%CERTS%\client_enc.key"

if "%SERVER_HW_SIGN_IDX%"=="" set "SERVER_HW_SIGN_IDX=1"
if "%SERVER_HW_ENC_IDX%"=="" set "SERVER_HW_ENC_IDX=1"
if "%CLIENT_HW_SIGN_IDX%"=="" set "CLIENT_HW_SIGN_IDX=2"
if "%CLIENT_HW_ENC_IDX%"=="" set "CLIENT_HW_ENC_IDX=2"

call :apply_cert_profile server "%SERVER_CERT_PROFILE%"
if errorlevel 1 exit /b 1
call :apply_cert_profile client "%CLIENT_CERT_PROFILE%"
if errorlevel 1 exit /b 1

if /I not "%IMPORT_KEYS%"=="0" (
    echo [CMD] call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=sm2
    call "%~dp0import_sdf_keys.bat" IMPORT_GROUP=sm2
    if errorlevel 1 exit /b 1
)

echo.
echo ================================================================
echo   NTLS SM2 密码套件全组合测试
echo   2 个密码套件 x 4 种密钥组合 = 8 个测试场景
echo ================================================================

taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
ping -n 3 127.0.0.1 >nul 2>&1

:: ============================================================
::  1. ECC-SM2-SM4-CBC-SM3 | Svr: SW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 ^| Svr:SW ^| Cli:SW
call :handshake 25101 ECC-SM2-SM4-CBC-SM3 sw sw

:: ============================================================
::  2. ECC-SM2-SM4-CBC-SM3 | Svr: HW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 ^| Svr:HW ^| Cli:SW
call :handshake 25102 ECC-SM2-SM4-CBC-SM3 hw sw

:: ============================================================
::  3. ECC-SM2-SM4-CBC-SM3 | Svr: SW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 ^| Svr:SW ^| Cli:HW
call :handshake 25103 ECC-SM2-SM4-CBC-SM3 sw hw

:: ============================================================
::  4. ECC-SM2-SM4-CBC-SM3 | Svr: HW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECC-SM2-SM4-CBC-SM3 ^| Svr:HW ^| Cli:HW
call :handshake 25104 ECC-SM2-SM4-CBC-SM3 hw hw

:: ============================================================
::  ECDHE 测试前设备冷却，确保前序 HW 测试释放 SDF 设备资源
:: ============================================================
echo.
echo  [冷却等待 5 秒 - 释放 SDF 设备资源]
taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
ping -n 6 127.0.0.1 >nul 2>&1

:: ============================================================
::  5. ECDHE-SM2-SM4-CBC-SM3 | Svr: SW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 ^| Svr:SW ^| Cli:SW
call :handshake 25105 ECDHE-SM2-SM4-CBC-SM3 sw sw

:: ============================================================
::  6. ECDHE-SM2-SM4-CBC-SM3 | Svr: HW | Cli: SW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 ^| Svr:HW ^| Cli:SW
call :handshake 25106 ECDHE-SM2-SM4-CBC-SM3 hw sw

:: ============================================================
::  7. ECDHE-SM2-SM4-CBC-SM3 | Svr: SW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 ^| Svr:SW ^| Cli:HW
call :handshake 25107 ECDHE-SM2-SM4-CBC-SM3 sw hw

:: ============================================================
::  8. ECDHE-SM2-SM4-CBC-SM3 | Svr: HW | Cli: HW
:: ============================================================
set /a NUM+=1
echo.
echo  [%NUM%] ECDHE-SM2-SM4-CBC-SM3 ^| Svr:HW ^| Cli:HW
call :handshake 25108 ECDHE-SM2-SM4-CBC-SM3 hw hw

:: ============================================================
:: 汇总
:: ============================================================
echo.
echo ================================================================
echo   测试汇总: 通过 %PASS% / %NUM%, 失败 %FAIL% / %NUM%
echo ================================================================

taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
exit /b

:: ============================================================
::  :handshake 子程序
::  %1=端口  %2=密码套件  %3=服务端密钥类型(sw/hw)  %4=客户端密钥类型(sw/hw)
:: ============================================================
:handshake
set "HP=%~1"
set "HC=%~2"
set "SKT=%~3"
set "CKT=%~4"

set "SF=%OUTDIR%\ntls_svr_%HP%.txt"
set "CF=%OUTDIR%\ntls_cli_%HP%.txt"

:: 构建服务端命令
set "SCMD=.\openssl.exe s_server -ntls -enable_ntls -accept %HP%"
if "%SKT%"=="sw" (
    set "SCMD=%SCMD% -sign_cert %SERVER_SIGN_CERT% -enc_cert %SERVER_ENC_CERT% -sign_key %SERVER_SIGN_KEY% -enc_key %SERVER_ENC_KEY%"
) else (
    set "SCMD=%SCMD% -sign_cert %SERVER_SIGN_CERT% -enc_cert %SERVER_ENC_CERT% -sign_key sdf:key=%SERVER_HW_SIGN_IDX%;type=sign -enc_key sdf:key=%SERVER_HW_ENC_IDX%;type=enc -provider sdfprov -provider default"
)
set "SCMD=%SCMD% -www -CAfile %CAFILE% -cipher %HC%"

:: 构建客户端命令
set "CCMD=.\openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:%HP%"
if "%CKT%"=="sw" (
    set "CCMD=%CCMD% -sign_cert %CLIENT_SIGN_CERT% -enc_cert %CLIENT_ENC_CERT% -sign_key %CLIENT_SIGN_KEY% -enc_key %CLIENT_ENC_KEY%"
) else (
    set "CCMD=%CCMD% -sign_cert %CLIENT_SIGN_CERT% -enc_cert %CLIENT_ENC_CERT% -sign_key sdf:key=%CLIENT_HW_SIGN_IDX%;type=sign -enc_key sdf:key=%CLIENT_HW_ENC_IDX%;type=enc -provider sdfprov -provider default"
)
set "CCMD=%CCMD% -CAfile %CAFILE% -cipher %HC%"

echo [CMD][server] %SCMD%
start /b cmd /c "%SCMD% > %SF% 2>&1"

:: 服务端启动等待，HW 密钥需要更长初始化时间
if "%SKT%"=="hw" (
    ping -n 5 127.0.0.1 >nul 2>&1
) else (
    ping -n 3 127.0.0.1 >nul 2>&1
)

:: 后台运行客户端并做超时检测，避免客户端卡死阻塞整个脚本
:: 客户端输出写入对应端口日志
echo [CMD][client] echo Q ^| %CCMD%
start /b cmd /c "echo Q | %CCMD% > %CF% 2>&1"

:: 最多等待 15 秒，每秒检查客户端输出是否已有 Cipher is
set /a TIMEOUT=0
:wait_loop
ping -n 2 127.0.0.1 >nul 2>&1
set /a TIMEOUT+=1
if %TIMEOUT% GEQ 15 goto :timeout_check
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :client_done
goto :wait_loop

:timeout_check
:: 超时后强制终止
taskkill /f /im openssl.exe >nul 2>&1
echo     [TIMEOUT] 客户端等待超时，已强制终止

:client_done

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

:: 每个用例结束后清理，HW 测试需要更长等待确保设备资源释放
taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
if "%SKT%"=="hw" (
    ping -n 4 127.0.0.1 >nul 2>&1
) else (
    ping -n 2 127.0.0.1 >nul 2>&1
)
goto :eof

:apply_cert_profile
set "APSIDE=%~1"
set "APPROFILE=%~2"
if "%APPROFILE%"=="" set "APPROFILE=sm2"
if /I "%APPROFILE%"=="sm2" exit /b 0
if /I "%APPROFILE%"=="rsa2048" goto :apply_cert_profile_unsupported
if /I "%APPROFILE%"=="rsa3072" goto :apply_cert_profile_unsupported
if /I "%APPROFILE%"=="rsa4096" goto :apply_cert_profile_unsupported
echo FAIL: unknown %APSIDE% certificate profile "%APPROFILE%"
exit /b 1

:apply_cert_profile_unsupported
echo FAIL: test_ntls_full only supports SM2 certificate profiles for NTLS; got %APSIDE% profile "%APPROFILE%"
exit /b 1
