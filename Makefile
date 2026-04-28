# Makefile for CVE-2025-6349/8045 POC
# Targets: Android 16, Pixel 7/8/9 (r53p0-r54p1)
# Uses GCC cross-compiler (alternative to NDK clang)

CC = aarch64-linux-gnu-gcc
CFLAGS = -O2 -g -Wall -fPIC -static
LDFLAGS = -lpthread -lm -lrt

# Note: This builds static binaries for maximum compatibility
# across different Android devices.

TARGET = mali_uaf_poc
TARGET_PIXEL9 = mali_pixel9_poc
TARGET_STRATEGY3 = poc_strategy3
SOURCES = poc_cve_2025_6349_8045.c
SOURCES_PIXEL9 = poc_cve_pixel9.c
SOURCES_STRATEGY3 = poc_strategy3.c

all: $(TARGET) $(TARGET_PIXEL9) $(TARGET_STRATEGY3)

$(TARGET): $(SOURCES)
	@echo "[*] Building generic POC with $(CC)..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[*] Built: $@ ($(shell du -h $@ | cut -f1))"
	@echo "[*] Push: adb push $@ /data/local/tmp/"
	@echo "[*] Run:  adb shell chmod +x /data/local/tmp/$@ && adb shell /data/local/tmp/$@"

$(TARGET_PIXEL9): $(SOURCES_PIXEL9)
	@echo "[*] Building Pixel 9 POC with $(CC)..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[*] Built: $@ ($(shell du -h $@ | cut -f1))"
	@echo "[*] Push: adb push $@ /data/local/tmp/"
	@echo "[*] Run:  adb shell chmod +x /data/local/tmp/$@ && adb shell /data/local/tmp/$@ 3071"

$(TARGET_STRATEGY3): $(SOURCES_STRATEGY3)
	@echo "[*] Building Strategy 3 (GPU Hang) POC with $(CC)..."
	$(CC) $(CFLAGS) -o $@ $< -ldl -lpthread
	@echo "[*] Built: $@ ($(shell du -h $@ | cut -f1))"
	@echo "[*] Push: adb push $@ /data/local/tmp/"
	@echo "[*] Run:  adb shell chmod +x /data/local/tmp/$@ && adb shell /data/local/tmp/$@"

clean:
	rm -f $(TARGET) $(TARGET_PIXEL9) $(TARGET_STRATEGY3)

test: $(TARGET_STRATEGY3)
	@echo "[*] Deploying Strategy 3 to device..."
	adb push $(TARGET_STRATEGY3) /data/local/tmp/
	adb shell chmod +x /data/local/tmp/$(TARGET_STRATEGY3)
	@echo "[*] Running GPU hang exploit..."
	adb shell /data/local/tmp/$(TARGET_STRATEGY3)

check-dmesg:
	@echo "[*] Checking dmesg for UAF indicators..."
	adb shell dmesg | grep -iE "(kasan|use-after-free|double-free|slob|slab|mali|kbase)" | tail -100 || true

verify: $(TARGET_STRATEGY3)
	@echo "[*] Running full Strategy 3 test sequence..."
	adb push $(TARGET_STRATEGY3) /data/local/tmp/
	adb shell chmod +x /data/local/tmp/$(TARGET_STRATEGY3)
	adb shell /data/local/tmp/$(TARGET_STRATEGY3) || true
	@echo ""
	@echo "[*] Dmesg output:"
	adb shell dmesg | tail -200 | grep -iE "(kasan|use-after-free|double-free|slob|slab|mali|kbase)" || echo "(no indicators found)"

.PHONY: all clean test check-dmesg verify

# === Android NDK Build Alternative ===
# If you have Android NDK installed and want to use clang:
#
# export ANDROID_NDK_HOME=/path/to/android-ndk-r26b
# NDK_CC=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang
#
# ndk-build:
#	$(NDK_CC) -O2 -g -Wall -o $(TARGET) $(SOURCES) -lpthread -llog -static
#
# Note: NDK build may require linking against liblog, libm, etc.


