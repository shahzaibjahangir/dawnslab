# Google Pixel Mali GPU Driver Analysis — Methodology

## Overview
ARM Mali GPU kernel driver (`mali_kbase`) is a primary attack surface on Pixel devices. This reference covers Mali-specific vulnerability patterns, analysis techniques, and debugging approaches.

## Mali Architecture Basics

### Job Chain (JC) Execution Model
- GPU jobs submitted as **Job Chains** — sequences of **Job Slots**
- Each job slot contains **Job Head** (start) and **Job Tail** (end) pointers
- Jobs processed by GPU hardware asynchronously
- Userspace → `mali_kbase` ioctl → Job Chain → GPU execution

### Key Structures
```
kbase_context          # Per-process GPU context
kbase_jd_context       # Job dispatch context
kbase_jd_atom          # Single job atom
kbase_va_region        # GPU virtual memory region (heap)
kbase_mem_allocator    # Memory allocator (OS memory)
kbase_jd_submit        # Submit path - major attack surface
```

### Memory Management
- **GPU VA** — Virtual address space managed by `kbase_va_region`
- **GPU PA** — Physical addresses backed by OS pages
- **Two-level page tables** — GPU page tables managed by driver
- **Heap regions** — `kbase_mem_allocator` (kctx, os)

### Command Submission Flow
```
Userspace:  ioctl(KBASE_IOCTL_JD_SUBMIT)
     ↓
kbase_jd_submit()  ← Entry point
     ↓
Parse job atoms from userspace struct
     ↓
For each atom:
  - Validate job slot
  - Map resources (mem, sync)
  - Check dependencies
     ↓
kbase_jd_submit_atom()
     ↓
Queue to runpool (GPU scheduler)
     ↓
GPU executes job chain asynchronously
```

## Attack Surface

### Primary Ioctl Targets
```c
KBASE_IOCTL_VERSION_CHECK       // Uninteresting
KBASE_IOCTL_SET_FLAGS           // Context flags
KBASE_IOCTL_MEM_ALLOC           // Memory allocation
KBASE_IOCTL_MEM_FREE            // Memory free
KBASE_IOCTL_MEM_COMMIT          // Commit pages
KBASE_IOCTL_MEM_QUERY_NEEDS_PAGES
KBASE_IOCTL_MEM_MAP             // Map to GPU VA
KBASE_IOCTL_MEM_UNMAP           // Unmap from GPU VA
KBASE_IOCTL_MEM_ALIAS           // Create alias regions
KBASE_IOCTL_CTX_MODIFY          // Modify context
KBASE_IOCTL_JD_SUBMIT           // Job submission (critical!)
KBASE_IOCTL_EVENT_GET           // Event wait
KBASE_IOCTL_EVENT_SET           // Event set
KBASE_IOCTL_GET_CONTEXT_ID      // Get context ID
KBASE_IOCTL_SOFT_STOP           // Stop job
KBASE_IOCTL_POST_TERM           // Post termination
KBASE_IOCTL_PRIMITIVE_INSTR     // Primitive instructions
```

### Critical Paths

#### 1. Job Submission (`KBASE_IOCTL_JD_SUBMIT`)
- Processes `kbase_uk_submit` from userspace
- Copies job atoms into kernel
- Validates and queues for execution
- **Vulnerabilities:**
  - OOB access when parsing atoms
  - Use-after-free if atom freed during execution
  - Integer overflow in size calculations
  - Missing validation of atom dependencies
  - Race conditions between submit and free

#### 2. Memory Allocation (`KBASE_IOCTL_MEM_ALLOC`)
- Allocates GPU VA regions
- Backs with OS memory pages
- **Vulnerabilities:**
  - Integer overflow in size × count
  - OOB in region tracking
  - Double free / use-after-free
  - Memory leakage (insufficient cleanup on error paths)
  - Insufficient permissions check on region type

#### 3. Memory Commit (`KBASE_IOCTL_MEM_COMMIT`)
- Physically commits backing pages
- **Vulnerabilities:**
  - Exceeding committed limit
  - Use-after-free if pages freed during commit
  - Races between commit and GPU execution

#### 4. GPU VA Mapping (`KBASE_IOCTL_MEM_MAP`)
- Maps allocated regions into GPU VA space
- **Vulnerabilities:**
  - OOB in region calculations
  - Overlapping regions (should be prevented)
  - Insufficient validation of offset/size

## Historical Mali Vulnerabilities — Pattern Analysis

### CVE-2021-28663 — Mali Use-After-Free (Google)
- **Component:** `mali_kbase` kernel driver
- **Type:** Use-after-free in job submission
- **Root Cause:** Race condition between job completion and atom reference counting
- **Primitive:** Kernel info leak / potential LPE
- **Fix:** Proper reference counting, ordering of free vs completion

### CVE-2021-28664 — Mali OOB Write (Google)
- **Component:** `mali_kbase` kernel driver  
- **Type:** Out-of-bounds write in heap management
- **Root Cause:** Integer overflow in size calculation when allocating GPU objects
- **Primitive:** Arbitrary write in kernel context
- **Fix:** Bounds check before allocation

### CVE-2022-20452 — Mali Use-After-Free (Qualcomm)
- **Component:** `mali_kbase` kernel driver
- **Type:** Use-afer-free in memory aliasing
- **Root Cause:** Double free in error path of `kbase_mem_aliasing`
- **Primitive:** Local privilege escalation
- **Fix:** Proper refcounting in error path

### CVE-2022-42704 — Mali Integer Overflow (Samsung)
- **Component:** `mali_kbase` kernel driver
- **Type:** Integer overflow → heap overflow
- **Root Cause:** `count * stride` overflow in GPU vertex buffer allocation
- **Primitive:** Kernel memory corruption
- **Fix:** Check overflow before allocation

### Analysis Pattern
Most Mali bugs follow these patterns:
1. **Reference counting errors** — Missing `kref_get()` or `kref_put()` around job atoms
2. **Races** — Between CPU free path and GPU completion interrupt
3. **Integer overflow** — Size × count calculations
4. **Missing validation** — Userspace offsets/sizes not validated
5. **Error path bugs** — Cleanup on error doesn't match init path

## Debugging Mali Driver

### Setting Up Debug Environment

1. **Get kernel symbols:**
```bash
adb root
adb shell cat /proc/kallsyms | grep mali > mali_syms.txt
adb shell cat /proc/kallsyms | grep kbase > kbase_syms.txt
```

2. **Enable Mali debugfs:**
```bash
adb shell mount -t debugfs none /sys/kernel/debug
adb shell ls /sys/kernel/debug/mali0/
# Look for: mem, timeline, atoms, jobs
```

3. **Enable kernel tracing for Mali:**
```bash
adb shell "echo mali:* > /sys/kernel/debug/tracing/set_ftrace_filter"
adb shell "echo function > /sys/kernel/debug/tracing/current_tracer"
adb shell "echo 1 > /sys/kernel/debug/tracing/tracing_on"
```

4. **Enable GPU-specific kernel messages:**
```bash
adb shell "echo 0xFFFFFFFF > /sys/module/mali_kbase/parameters/driver_debug_level"
# Or at boot: androidboot.mali_debug_level=0xFFFFFFFF
```

### Key Debug Files

```
/sys/kernel/debug/mali0/version          # Mali GPU version
/sys/kernel/debug/mali0/mem              # GPU memory usage
/sys/kernel/debug/mali0/timeline         # Job timeline
/sys/kernel/debug/mali0/atoms            # Active atoms
/sys/kernel/debug/mali0/jobs             # Job queue
/sys/kernel/debug/mali0/mmu              # MMU state
/sys/kernel/debug/mali0/pm               # Power management
```

### Debugging a Mali Crash

#### Step 1: Collect crash data
```bash
adb shell dmesg -c | tee mali_crash.log
adb shell cat /sys/kernel/debug/mali0/atoms
adb shell cat /sys/kernel/debug/mali0/timeline
```

#### Step 2: Analyze KASAN report
Look for:
- Which Mali function crashed
- Memory type (slab-out-of-bounds, use-after-free)
- Alloc and free stack traces (for UAF)

#### Step 3: Trace GPU execution
```bash
# Enable MALI_TIMELINE_TRACE
adb shell "echo 1 > /sys/module/mali_kbase/parameters/mali_timeline_trace_enable"

# Run reproducer
./poc_trigger_crash

# Check timeline
adb shell cat /sys/kernel/debug/mali0/timeline
```

#### Step 4: Inspect atom state
```bash
# Dump atoms before/after crash
adb shell "echo dump_atoms > /sys/kernel/debug/mali0/atoms"
```

### KGDB with Mali

```bash
# On target
echo g > /proc/sysrq-trigger

# On host, after connecting:
gdb vmlinux
(gdb) add-symbol-file drivers/gpu/mali/mali_kbase.ko
(gdb) info functions kbase
(gdb) break kbase_jd_submit
(gdb) break kbase_jd_submit_external_resources
(gdb) break kbase_mem_alloc
(gdb) continue
```

## Code Review Checklist

When analyzing `mali_kbase` code, check:

### For KBase Context
- [ ] `kbase_context` lifecycle — proper `kref` usage in `kbasep_js_runpool_release_ctx()`
- [ ] `kbase_create_context()` error paths — all allocations freed
- [ ] `kbase_destroy_context()` cleanup order — GPU jobs stopped before free

### For Job Submission
- [ ] `kbase_jd_submit()` — atom count validation against `BASE_JD_ATOM_COUNT_MAX`
- [ ] `kbase_jd_submit()` — `copy_from_user()` size calculation checked
- [ ] `kbase_jd_submit()` — `kbase_jd_submit_atom()` failure rollback
- [ ] `kbase_jd_submit_atom()` — job slot index validation
- [ ] `kbase_jd_submit_atom()` — dependency atom pointers validated
- [ ] `kbase_jd_submit_external_resources()` — resource count validated
- [ ] `kbase_jd_submit_external_resources()` — each resource mapped correctly
- [ ] `kbase_mem_allocator_alloc()` — integer overflow in size
- [ ] `kbase_va_region_alloc()` — region size fits in VA space

### For Memory Allocation
- [ ] `kbase_mem_alloc()` — `size` validated (not 0, not too large)
- [ ] `kbase_mem_alloc()` — `size * pagesize` checked for overflow
- [ ] `kbase_mem_commit()` — new commit doesn't exceed total alloc size
- [ ] `kbase_mem_commit()` — page array reallocation failure handled
- [ ] `kbase_mem_free()` — double-free prevented
- [ ] `kbase_mem_free()` — region removed from GPU VA before free
- [ ] `kbase_mem_aliasing()` — offset/size bounds checked
- [ ] `kbase_mem_aliasing()` — new region doesn't overlap existing

### For Synchronization
- [ ] `kbasep_js_runpool_release_ctx()` — proper locking with JS
- [ ] `kbase_jd_submit()` — `jctx.lock` held during submission
- [ ] `kbase_jd_done()` — atom completion with proper locks
- [ ] Job atom `kref` — incremented before submit, decremented on done

### For Error Paths
- [ ] `kbase_jd_submit()` — all error paths free atoms
- [ ] `kbase_jd_submit_external_resources()` — cleanup on partial failure
- [ ] `kbase_mem_alloc()` — region freed on failure

### For GPU Access
- [ ] `kbasep_syncset()` — userspace copy validated
- [ ] GPU command buffers — bounds checked before GPU access
- [ ] `kbasep_jd_submit_soft_job()` — software job validation

## Exploitation Primitives

### Common Mali Primitives

#### 1. Arbitrary Write (OOB Write)
- Write controlled data to kernel heap
- Can corrupt adjacent objects
- Target: `kbase_va_region`, `kbase_context`, function pointers
- Exploitation: Overwrite `ops` table or adjacent object metadata

#### 2. Use-After-Free (UAF)
- Free GPU object but keep reference
- Reallocate with controlled data
- Trigger GPU access to corrupted object
- Exploitation: Type confusion, controlled vtable/code execution

#### 3. Integer Overflow → Heap Overflow
- Wrap allocation size to be small
- Write more data than allocated
- Corrupt adjacent slab object
- Exploitation: Adjacent object overwrite

#### 4. Memory Info Leak
- Read uninitialized GPU memory
- Read freed GPU memory
- Leak kernel pointers
- Exploitation: KASLR bypass

#### 5. GPU Page Table Manipulation
- Map GPU VA to arbitrary physical page
- If PFN validation bypassed
- Exploitation: Direct kernel memory read/write

## References

- ARM Mali Driver Source: https://developer.arm.com/ip-products/graphics
- Android Security Bulletins: https://source.android.com/docs/security/bulletin
- Google Project Zero (Mali): https://googleprojectzero.blogspot.com/search?q=mali
- ARM Security Notices: https://developer.arm.com/security-notices
- Samsung Security Response: https://security.samsung.com/
- Qualcomm Security: https://www.qualcomm.com/company/product-security/bulletins