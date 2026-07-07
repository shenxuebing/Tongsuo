@echo off
chcp 65001 >nul 2>&1
call "D:\Visual Studio 2022\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1
cd /d E:\vs2022workspace\Tongsuo\apps

set "OPENSSL_CONF=%CD%\openssl.cnf"
set PASS=0
set FAIL=0
set NUM=0
if not exist ..\ntls_out mkdir ..\ntls_out
set "CERTS=..\test\certs\sm2"
set "CAFILE=%CERTS%\chain-ca.crt"

echo.
echo ================================================================
echo   NTLS SM2 密码套件全组合测试
echo   2 密码套件 x 4 密钥组合 = 8 测试场景
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
::  ECDHE 测试前设备冷却 (前序 HW 测试需要释放 SDF 设备资源)
:: ============================================================
echo.
echo  [冷却等待 5 秒 - 释放 SDF 设备资源...]
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
echo   测试汇总:  通过 %PASS% / %NUM%,  失败 %FAIL% / %NUM%
echo ================================================================

del /q ..\ntls_out\* >nul 2>&1
rmdir ..\ntls_out >nul 2>&1
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

set "SF=..\ntls_out\svr_%HP%.txt"
set "CF=..\ntls_out\cli_%HP%.txt"

:: 构建服务端命令
set "SCMD=.\openssl.exe s_server -ntls -enable_ntls -accept %HP%"
if "%SKT%"=="sw" (
    set "SCMD=%SCMD% -sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key %CERTS%\server_sign.key -enc_key %CERTS%\server_enc.key"
) else (
    set "SCMD=%SCMD% -sign_cert %CERTS%\server_sign.crt -enc_cert %CERTS%\server_enc.crt -sign_key sdf:key=0;type=sign -enc_key sdf:key=0;type=enc -provider sdfprov -provider default"
)
set "SCMD=%SCMD% -www -CAfile %CAFILE% -cipher %HC%"

:: 构建客户端命令
set "CCMD=.\openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:%HP%"
if "%CKT%"=="sw" (
    set "CCMD=%CCMD% -sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key %CERTS%\client_sign.key -enc_key %CERTS%\client_enc.key"
) else (
    set "CCMD=%CCMD% -sign_cert %CERTS%\client_sign.crt -enc_cert %CERTS%\client_enc.crt -sign_key sdf:key=1;type=sign -enc_key sdf:key=1;type=enc -provider sdfprov -provider default"
)
set "CCMD=%CCMD% -CAfile %CAFILE% -cipher %HC%"

start /b cmd /c "%SCMD% > %SF% 2>&1"

:: 服务端启动等待 (HW 密钥需要更长初始化时间)
if "%SKT%"=="hw" (
    ping -n 5 127.0.0.1 >nul 2>&1
) else (
    ping -n 3 127.0.0.1 >nul 2>&1
)

:: 使用后台启动 + 超时检测（避免客户端卡死阻塞整个脚本）
:: 客户端后台运行，写入输出文件
start /b cmd /c "echo Q | %CCMD% > %CF% 2>&1"

:: 超时等待：最多等待 15 秒，每秒检查输出文件是否已有 Cipher is
set /a TIMEOUT=0
:wait_loop
ping -n 2 127.0.0.1 >nul 2>&1
set /a TIMEOUT+=1
if %TIMEOUT% GEQ 15 goto :timeout_check
findstr /C:"Cipher is" "%CF%" >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :client_done
goto :wait_loop

:timeout_check
:: 超时后强制终止客户端
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

:: 测试结束后清理 - HW 测试需要更长等待确保设备资源释放
taskkill /f /im openssl.exe >nul 2>&1
del /f /q yj.db-shm yj.db-wal >nul 2>&1
if "%SKT%"=="hw" (
    ping -n 4 127.0.0.1 >nul 2>&1
) else (
    ping -n 2 127.0.0.1 >nul 2>&1
)
goto :eof
