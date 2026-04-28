# Shaby's Tech House — Active Task Assignments

## TASK [T-001]: POC Race Condition Implementation ⚠️ IN_PROGRESS
**Assigned to:** Jax (CODER)  
**Priority:** CRITICAL  
**Status:** In Progress (Started: 2026-04-25 19:30 UTC)  

### Objective
Implement the race condition trigger between:
- `KBASE_IOCTL_KCPU_QUEUE_ENQUEUE` (CQS_WAIT + FENCE_SIGNAL → timeout)
- `KBASE_IOCTL_CS_CPU_QUEUE_DUMP` (buffer allocation during race window)

### Expected Result
- Double-free of kmalloc-large page (order-0, 4KB)
- KASAN report: "slab-use-after-free" or "double-free"
- Confirmed via dmesg

### Deliverables
1. `poc_race_trigger.c` — Race trigger code
2. `exploit_uaf.c` — UAF exploitation via GPU memory
3. Test script for Pixel 6/7/8 devices
4. dmesg log showing UAF evidence

### Technical Details
```c
// Race sequence
1. enqueue_thread: ioctl(KCPU_QUEUE_ENQUEUE) with CQS_WAIT
   → Starts fence_signal_timeout (3s timer)
2. monitor_thread: read() for dump notification
   → Detects dump_print timeout (3s elapsed)
3. monitor_thread: ioctl(CS_CPU_QUEUE_DUMP) during race window
   → kbase_csf_cpu_queue_dump_buffer() called
   → kfree(old_buffer) then kfree(new_buffer) [DOUBLE FREE!]
   → cpu_queue.buffer left dangling
```

### Verification Checklist
- [ ] Race trigger compiles without errors
- [ ] Can trigger on test device (Pixel 6/7 emulator or hardware)
- [ ] dmesg shows: `"kasan: slab-use-after-free in kbasep_csf_cpu_queue_dump_buffer"`
- [ ] Physical page tracking confirms same page reused
- [ ] GPU memory mmap shows corruption pattern

### Dependencies
None — standalone POC

### Known Issues
- Requires Mali GPU device (Pixel 6/7/8/9)
- Needs KASAN-enabled kernel or dmesg access
- May need root for /dev/mali access

---

## TASK [T-002]: GPU Memory Mapping & Page Reclaim ⏳ PENDING
**Assigned to:** Rhea (CODER)  
**Priority:** CRITICAL  
**Status:** Pending (depends on T-001 confirmation)

### Objective
Reclaim the freed kmalloc-large page via GPU memory allocation and map to userspace.

### Implementation
```c
// 1. Allocate GPU memory (should reclaim freed page)
struct kbase_uk_mem_alloc alloc;
alloc.in.flags = BASE_MEM_SAME_VA;
alloc.in.va_pages = 1;
ioctl(KBASE_IOCTL_MEM_ALLOC, &alloc);

// 2. Commit pages
struct kbase_uk_mem_commit commit;
commit.in.va = alloc.out.va;
commit.in.nents = 1;
ioctl(KBASE_IOCTL_MEM_COMMIT, &commit);

// 3. Map to userspace
void *map = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                 MAP_SHARED, mali_fd, alloc.out.va);
```

### Verification
- /proc/self/pagemap shows identical physical page address
- Write to GPU memory affects CPU-accessible data
- Same PFN as freed kmalloc-large page

### Dependencies
- T-001 (confirmed race/double-free)

---

## TASK [T-003]: Kernel Debugging & UAF Validation 🔍 PENDING
**Assigned to:** Silas (DEBUGGER)  
**Priority:** CRITICAL  
**Status:** Pending

### Objective
Confirm UAF via kernel debugging tools and analyze crash dumps.

### Tools
- KGDB remote debugging
- KASAN-enabled kernel (Pixel test device)
- ftrace/kprobes for dynamic analysis
- dmesg log analysis

### Deliverables
1. KASAN report analysis
2. KGDB session transcript showing freed page access
3. Physical address tracking (PFN mapping)
4. Stack traces for alloc/free paths

### Verification
- [ ] KASAN confirms UAF (not false positive)
- [ ] KGDB shows instruction pointer in dump_buffer path
- [ ] Physical page refcount analysis
- [ ] Timeline of alloc → free1 → free2 → reuse

### Dependencies
- T-001 (race trigger)
- T-002 (page reclaim proof)
- Test device with debug kernel

---

## TASK [T-004]: Page Table Manipulation Primitive 🎯 PENDING
**Assigned to:** Vega (REVERSE-ENGINEER)  
**Priority:** HIGH  
**Status:** Pending

### Objective
Develop technique to corrupt page tables via UAF for arbitrary physical R/W.

### ARM64 MMU Targets
- Level 0/1/2 page table entries (PTEs)
- TTBR0_EL1 (user space page tables)
- Section/block mappings for kernel data

### Strategy
```
1. UAF page is kmalloc-large (order-0, 4KB)
2. Reclaim as GPU page table page (L2/L3)
3. Modify PTE to remap physical address:
   - init_cred (uid=0) → userspace accessible
   - modprobe_path → "/system/bin/sh"
   - Kernel text → ROP gadget
4. Trigger TLB flush
5. Read/write arbitrary physical memory
```

### Known Offsets (Pixel 6/7 - Android 13/14)
- init_cred: ~0xFFFF0000XXXX (kernel base + offset)
- modprobe_path: ~0xFFFF0000XXXX
- Kernel text base: 0xFFFF00000000 (typical)

*Note: Offsets vary by kernel version — will determine via kallsyms*

### Deliverables
1. `ptw_corrupt.c` — Page table walk corruption
2. `phys_rw.c` — Arbitrary physical R/W using remapped PTEs
3. `cred_overwrite.c` — Privilege escalation proof

### Verification
- Read kernel memory from userspace (e.g., /dev/kmsg)
- uid becomes 0 (root shell)
- SELinux can be disabled (setenforce 0)

### Dependencies
- T-002 (GPU memory mapping)
- T-003 (UAF confirmation)
- Physical address leak (from KASAN or /proc/kallsyms)

---

## TASK [T-005]: Full Exploit Integration 💀 PENDING
**Assigned to:** Orion (REVERSE-ENGINEER)  
**Priority:** HIGH  
**Status:** Pending

### Objective
Combine all primitives into complete privilege escalation exploit.

### Exploit Chain
```
[Userspace]
    ↓
1. Trigger race (T-001) → Double-free
    ↓
2. Reclaim via GPU (T-002) → Page UAF
    ↓
3. Map corrupted page (T-002) → Controlled data
    ↓
4. Corrupt PTE (T-004) → Arbitrary phys R/W
    ↓
5. Overwrite init_cred (T-004) → uid=0, gid=0
    ↓
6. Disable SELinux (T-004) → setenforce 0
    ↓
[Root SHELL]
```

### Deliverables
1. `exploit.c` — Complete exploit (single file)
2. `Makefile` — Build configuration
3. `README.md` — Usage instructions
4. Test results on target devices

### Target Devices
- [ ] Pixel 6 (oriole) — Android 13/14, Kernel 5.10
- [ ] Pixel 7 (panther) — Android 14, Kernel 5.10  
- [ ] Pixel 8 (shiba) — Android 14, Kernel 5.10 (if vulnerable)

### Verification (Success Criteria)
```bash
$ ./exploit
[*] Triggering race condition...
[*] Double-free detected!
[*] Reclaiming page via GPU...
[*] Corrupting page tables...
[*] Overwriting credentials...
$ id
uid=0(root) gid=0(root) groups=0(root)
$ getenforce
Permissive
```

### Dependencies
- T-001, T-002, T-003, T-004 (all previous tasks)
- Device-specific kernel offsets

---

## TASK [T-006]: Documentation & Disclosure 📄 PENDING
**Assigned to:** Kael (LEAD)  
**Priority:** MEDIUM  
**Status:** Pending

### Objective
Document findings, create advisory, coordinate disclosure.

### Deliverables
1. **Technical Advisory** — Full vulnerability analysis
2. **Patch Recommendations** — Fix suggestions for AOSP
3. **Mitigation Guide** — Workarounds for users/enterprises
4. **Disclosure Timeline** — Coordinated release plan
5. **CVE Assignment** — Already assigned: CVE-2025-6349, CVE-2025-8045

### Target Recipients
- Google Android Security Team
- ARM Security Team
- AOSP maintainers (mali_kbase driver)
- Pixel device OEMs

### Timeline
- **Day 0:** Initial discovery (2026-04-25)
- **Day 7:** POC confirmation (T-001 complete)
- **Day 14:** Full exploit (T-005 complete)
- **Day 21:** Vendor notification
- **Day 90:** Public disclosure (if patched)

### Dependencies
- T-001 (confirmed vulnerability)
- T-005 (working exploit for impact demonstration)

---

## Progress Tracking

| Task | Status | Priority | Assigned | Start Date | Due Date |
|------|--------|----------|----------|------------|----------|
| T-001 | 🟡 In Progress | CRITICAL | Jax | 2026-04-25 | 2026-04-26 |
| T-002 | ⚪ Pending | CRITICAL | Rhea | TBD | 2026-04-28 |
| T-003 | ⚪ Pending | CRITICAL | Silas | TBD | 2026-04-29 |
| T-004 | ⚪ Pending | HIGH | Vega | TBD | 2026-05-03 |
| T-005 | ⚪ Pending | HIGH | Orion | TBD | 2026-05-06 |
| T-006 | ⚪ Pending | MEDIUM | Kael | TBD | 2026-05-10 |

**Legend:** 🟢 Complete | 🟡 In Progress | ⚪ Pending | 🔴 Blocked

---

*Last updated: 2026-04-25 19:30 UTC*  
*Shaby's Tech House R&D Lab*