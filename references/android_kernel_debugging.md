# Android Kernel Debugging — Methodology & Procedures

## Overview
This reference covers kernel debugging techniques specific to Android security research, focusing on exploit analysis, crash forensics, and vulnerability validation for LPE bugs in the Linux kernel subsystem.

## Kernel Configuration for Debugging

### Essential Debug Options
```
CONFIG_KASAN=y          # Kernel Address Sanitizer - detects OOB, UAF, etc
CONFIG_KASAN_INLINE=y   # More precise but overhead
CONFIG_KMSAN=y          # Kernel Memory Sanitizer (uninitialized memory)
CONFIG_UBSAN=y          # Undefined Behavior Sanitizer
CONFIG_DEBUG_LIST=y     # List corruption detection
CONFIG_DEBUG_SG=y       # Scatterlist debugging
CONFIG_DEBUG_NOTIFIERS=y
CONFIG_LOCKDEP=y        # Lock dependency validator
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_DEBUG_MUTEXES=y
CONFIG DEBUG_SHIRQ=y
CONFIG_DEBUG_PER_CPU_MAPS=y
CONFIG_STACKTRACE=y
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_FS=y
CONFIG_KALLSYMS=y       # Kernel symbol table (essential for crash analysis)
CONFIG_KALLSYMS_ALL=y
CONFIG_KDB=y            # Kernel debugger (if KGDB unavailable)
CONFIG_KGDB=y           # Remote kernel debugging
CONFIG_KGDB_SERIAL_CONSOLE=y
CONFIG_FRAME_POINTER=y  # Better stack traces
CONFIG_DEBUG_INFO=y     # Full debug symbols (DWARF)
CONFIG_DEBUG_INFO_DWARF4=y
CONFIG_FTRACE=y         # Function tracer
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_SCHED_TRACER=y
CONFIG_IRQSOFF_TRACER=y
CONFIG_BLOCK_EXT_DEVT=y
CONFIG_SECURITY_SELINUX=y
CONFIG_AUDIT=y
```

### SLUB Debugging (Slab Allocator)
```
CONFIG_SLUB_DEBUG=y     # Full slab debugging (causes overhead)
CONFIG_SLUB_DEBUG_ON=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_PAGE_OWNER=y
CONFIG_DEBUG_PAGEALLOC=y
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
```

## Crash Log Analysis

### Reading dmesg / kmsg
Key patterns to extract:

1. **Oops/BUG format:**
```
[  123.456789] BUG: KASAN: slab-out-of-bounds in function_name+0xXX/0xXX
[  123.456790] Write of size 8 at addr ffff888123456780 by task exploit/1234
[  123.456791] 
[  123.456792] CPU: 3 PID: 1234 Comm: exploit Tainted: G           OE
[  123.456793] Hardware name: Google Pixel 6 (DT)
[  123.456794] Call trace:
[  123.456795]  dump_stack_lvl+0xXX/0xXX
[  123.456796]  function_A+0xXX/0xXX
[  123.456797]  function_B+0xXX/0xXX  <-- Buggy function here
[  123.456798]  function_C+0xXX/0xXX
[  123.456799]  system_call_entry+0xXX/0xXX
[  123.456800] Code: XX XX XX XX XX (bad instruction)
```

2. **UAF (Use-After-Free):**
```
BUG: KASAN: slab-use-after-free in ...
Read/Write of size X at addr ... by task ...
Freed by task X, pid Y, age Z jiffies
Alloc: stack trace:
[<...>] function_alloc+0xXX/0xXX
[<...>] ...
Freed: stack trace:
[<...>] function_free+0xXX/0xXX
[<...>] ...
```

3. **Double-Free:**
```
BUG: KASAN: double-free or invalid free
```

4. **General Protection Fault (GPF):**
```
general protection fault, probably for non-canonical address
```

### Key Fields Interpretation

- **`Write of size X`** — Type of violation (write=corruption, read=info leak)
- **`at addr 0xffff...`** — Faulting address (kernel space vs userspace)
- **`by task name/pid`** — Which process triggered it
- **`Call trace`** — Stack backtrace at crash (find YOUR code in here)
- **`Code:`** — Disassembly at faulting instruction
- **`RIP:`** — Instruction pointer (where crash occurred)
- **`RSP:`** — Stack pointer (use for stack walk)

## KGDB Remote Debugging Setup

### On Target Device (Pixel):
```bash
# Enable KGDB over serial (usually via USB gadget)
echo ttyMSM0,115200n8 > /sys/module/kgdboc/parameters/kgdboc

# Enable KGDB
grep . /sys/module/kgdboc/parameters/kgdboc
echo g > /proc/sysrq-trigger  # Enter debugger
```

### On Host Machine:
```bash
# Connect via USB serial
sudo gdb vmlinux
(gdb) set remotebaud 115200
(gdb) target remote /dev/ttyUSB0

# Or over network (if kgdboc configured for net)
(gdb) target remote <device-ip>:6443

# Once connected
(gdb) continue                    # Resume execution
(gdb) bt                          # Backtrace
(gdb) info registers              # All registers
(gdb) disassemble function_name   # Disassemble
(gdb) x/10i $pc                   # Next 10 instructions
(gdb) x/40x $rsp                  # Stack dump
(gdb) x/gx addr                   # Examine memory
(gdb) info locals                 # Local variables
(gdb) list *address               # Source listing
```

### KGDB Commands Cheat Sheet
```
sysrq-g              # Enter KGDB on target
c / continue         # Continue execution
bt / backtrace       # Stack trace
info threads         # Thread listing
thread N             # Switch to thread N
info registers       # Register dump
x/Nx addr            # Hex dump N words from addr
x/Ni addr            # Disassemble N instructions
x/s addr             # Print string
x/40g addr           # Dump 40 giant words (64-bit)
print var            # Print variable
print *struct_ptr    # Dereference struct
print/x $reg         # Print register hex
stepi / si           # Single step instruction
nexti / ni           # Next instruction (skip calls)
finish               # Run to end of function
break *addr          # Set breakpoint
watch var            # Watch variable change
monitor <cmd>        # Pass to monitor (QEMU)
```

## Ftrace for Dynamic Analysis

### Enable Function Tracing:
```bash
cd /sys/kernel/debug/tracing

# Trace specific function
echo function > current_tracer
echo mali_kbase_jd_submit > set_ftrace_filter
cat trace_pipe &

# Trace all scheduler switches (for race detection)
echo sched_switch > current_tracer

# Trace IRQs
echo irqsoff > current_tracer

# Function graph (entry/exit with timestamps)
echo function_graph > current_tracer
```

### Custom Event Tracing:
```bash
# Add kprobe to your function
echo 'p:myprobe mali_kbase_jd_submit_external_resources u64 arg1=$arg1' > kprobe_events
echo 1 > events/kprobes/myprobe/enable
```

## KProbe for Dynamic Instrumentation

### Live Kernel Probes (no recompile):
```bash
# Register probe on function entry
echo 'p:probe_name function_name $arg1 $arg2' > /sys/kernel/debug/tracing/kprobe_events

# Register return probe
echo 'r:probe_name function_name' >> /sys/kernel/debug/tracing/kprobe_events

# Enable and view
echo 1 > /sys/kernel/debug/tracing/events/kprobes/probe_name/enable
cat /sys/kernel/debug/tracing/trace_pipe

# Remove
echo > /sys/kernel/debug/tracing/kprobe_events
```

### Example: Trace mali_kbase function arguments:
```bash
cd /sys/kernel/debug/tracing
echo 'p:mali_submit mali_kbase_jd_submit_external_resources size=%di:u64 nr_atoms=%si:u64' > kprobe_events
echo 1 > events/kprobes/mali_submit/enable
cat trace_pipe
```

## Memory Sanitizers

### KASAN (Kernel Address Sanitizer)
- Detects: OOB access, use-after-free, double-free
- Overhead: ~2x memory, ~2x CPU
- Interprets crash reports with stack traces
- Look for `slab-out-of-bounds` or `slab-use-after-free` in logs

### KMSAN (Kernel Memory Sanitizer)
- Detects: Use of uninitialized memory
- Slower (~3x), tracks shadow memory
- Rarely enabled for Android kernels

### UBSAN (Undefined Behavior Sanitizer)
- Detects: Integer overflow, shift overflow, misaligned access
- Minimal overhead

## Debugging Specific Bug Classes

### Use-After-Free
1. KASAN report shows "slab-use-after-free"
2. Note allocation and free stack traces
3. Find code path that reuses freed memory
4. Check if free can be triggered while reference still held
5. Patch: Add refcounting or ensure ordering

### Out-Of-Bounds Write
1. KASAN shows "slab-out-of-bounds" with offset
2. Correlated register values show buffer start
3. Calculate size used vs allocated
4. Check loop bounds, memcpy sizes, struct array indexing
5. Patch: Bounds check before copy

### Double-Free
1. KASAN shows "double-free or invalid free"
2. Check for race between two threads freeing same object
3. Look for missing lock protection around free path
4. Check reference counting logic
5. Patch: Atomic operations or lock protection

### NULL Pointer Dereference
1. Oops with "unable to handle kernel NULL pointer dereference"
2. Disassemble to find which pointer is NULL
3. Trace back to caller — should have validated input
4. Patch: Add NULL check at syscall boundary

### Integer Overflow → OOB
1. Allocation size calculation wraps (e.g., count * size < count)
2. Small allocation but loop uses unwrapped count
3. Patch: Check for overflow before allocation (`if (count && SIZE_MAX/count < size)`)

## Extracting Symbols from Device

```bash
# Get running kernel symbols
adb shell cat /proc/kallsyms > kallsyms.txt

# Filter for your driver (mali)
adb shell cat /proc/kallsyms | grep mali > mali_syms.txt

# For binder
adb shell cat /proc/kallsyms | grep binder > binder_syms.txt

# Get exact kernel version
adb shell uname -a
adb shell cat /proc/version
```

## Building Custom Debug Kernel

### AOSP Build (Pixel):
```bash
source build/envsetup.sh
lunch aosp_raven-userdebug  # Pixel 6

# Modify kernel config
cd kernel/google/raviole
./scripts/config --file .config --enable KASAN
./scripts/config --file .config --enable KASAN_INLINE
./scripts/config --file .config --enable DEBUG_INFO
./scripts/config --file .config --enable KGDB
make oldconfig

# Build
cd $ANDROID_BUILD_TOP
m kboot -j$(nproc)

# Flash
fastboot boot out/target/product/raven/...-boot.img
```

### Quick Recompile (existing tree):
```bash
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- menuconfig
# Enable debug options
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- -j$(nproc)
```

## Crash Analysis Workflow

1. **Capture crash** — `adb logcat -b kernel > crash.log`
2. **Extract PC** — Instruction pointer at crash
3. **Get symbols** — `aarch64-linux-android-addr2line` or kallsyms
4. **Disassemble** — `aarch64-linux-android-objdump -d vmlinux` around PC
5. **Map to source** — Debug info with `addr2line -e vmlinux PC`
6. **Trace backward** — Find how bad values reached this point
7. **Check boundaries** — Validate sizes, counts, offsets
8. **Check locks** — Verify proper synchronization
9. **Check refcounts** — Verify proper lifecycle
10. **Propose fix** — Bounds check, locking, or refcount change

## References
- https://source.android.com/docs/core/architecture/kernel/debug
- https://www.kernel.org/doc/html/latest/dev-tools/kgdb.html
- https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
- https://www.kernel.org/doc/html/latest/dev-tools/kprobes.html
- https://www.kernel.org/doc/html/latest/trace/ftrace.html