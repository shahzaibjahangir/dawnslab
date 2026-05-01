# Shaby's Tech House — Task Assignments
## CVE-2025-6349 / CVE-2025-8045 Exploitation

**Project Status:** Updated - 2026-04-30  
**Last Update:** Fixed dlopen + EGL loading, confirmed GPU hang blocker, documented remaining paths

### Quick Reference

| Task ID | Title | Assignee | Priority | Status | ETA |
|---------|-------|----------|----------|--------|-----|
| T-001 | POC Race Condition Implementation | Jax (CODER) | critical | 🚧 blocked | 2 days |
| T-002 | GPU Memory Mapping Analysis | Rhea (CODER) | critical | ✅ completed | 3 days |
| T-003 | Kernel Debugging & UAF Validation | Silas (DEBUGGER) | critical | ⏳ pending | 4 days |
| T-004 | Page Table Manipulation Primitive | Vega (RE) | high | ⏳ pending | 5 days |
| T-005 | Full Exploit Integration | Orion (RE) | high | ⏳ pending | 7 days |

---

### TASK [T-001]: POC Race Condition Implementation ⚠️ ACTIVE

**Assigned to:** Jax (CODER)  
**Priority:** critical  
**Status:** 🚧 blocked — GPU hang not achievable from unprivileged userspace

#### Updates (2026-04-30)

- **FIXED:** dlopen/libEGL loading — NDK build + dependency preload chain
- **FIXED:** Cookie exhaustion — separate FDs per strike thread
- **CONFIRMED:** KCPU queue creation works (ioctl 45, id=0)
- **CONFIRMED:** SSBO + barrier-deadlock shader compiles and dispatches
- **BLOCKED:** Mali G715 preempts ALL compute shaders (mid-frame preemption)
- **BLOCKED:** munmap SSBO while shader runs doesn't cause GPU hang
- **DISCOVERED:** `/sys/class/misc/mali0/device/trigger_fw_fault` can force CSF hang, but requires root
- **STRATEGY 3 VIABILITY DOWNGRADED:** ~20% from unprivileged (was 60-80%)

#### Blocker Details

The Arm Mali G715 GPU implements hardware mid-frame preemption. The CSF firmware
monitors shader execution and terminates any shader exceeding its time slice.
This means NO compute shader can run long enough to trigger the 3s CSF watchdog
that calls `kbasep_csf_cpu_queue_dump_print()`.

To trigger the CSF hang needed for the race, we need one of:
1. Root access → `trigger_fw_fault` sysfs → forces real CSF firmware hang
2. Custom kernel (Strategy 1) → debug ioctls re-enabled
3. Vulkan compute (untested) → may use different submission path
- Built optimized static binaries for Pixel 9 (r54p0)

#### Inputs

- KBASE_IOCTL_CS_CPU_QUEUE_DUMP ioctl interface (attempt)
- KBASE_IOCTL_KCPU_QUEUE_ENQUEUE interface  
- KBASE_IOCTL_KCPU_QUEUE_WAIT interface (new)
- dawnslab blog technical details
- GHSL-2024-356 exploit pattern

#### Expected Output

- Working race trigger code with improved coordination
- Evidence of double-free (dmesg UAF warning)
- Demonstration of kmalloc-large page reclaim via GPU
- Fallback paths for unavailable ioctls (6, 8)

#### Current Implementation

**Key Changes to `poc_cve_pixel9.c`:**

1. **Extension field fix:**
   ```c
   alloc_target.in.extension = 0;  // CRITICAL for r54p0!
   ```

2. **Alternative to ioctl 6:**
   ```c
   int gpu_free_via_commit(u64 gpu_va) {
       struct kbase_ioctl_mem_commit commit = {0};
       commit.gpu_va = gpu_va;
       commit.pages = 0;  /* De-commit all pages */
       return ioctl(mali_fd, KBASE_IOCTL_MEM_COMMIT, &commit);
   }
   ```

3. **Race coordination:**
   ```c
   struct kbase_ioctl_kcpu_queue_wait wait_req = {0};
   wait_req.id = qid;
   wait_req.timeout = 5000000000ull; // 5s timeout
   ```

#### Verification

- [ ] dmesg shows "kasan: slab-use-after-free" or "double-free"
- [ ] Can reclaim page via GPU allocation (hit rate > 60%)
- [ ] Memory contents show corruption pattern after reclaim
- [ ] Race window properly synchronized (3000-3071ms)
- [ ] Fallback paths work when primary ioctls unavailable

#### Dependencies

None (standalone, but benefits from rooted test device)

#### Known Issues

- ioctl 6 (MEM_FREE) returns ENOTTY on r54p0 → using commit-with-0 workaround
- ioctl 8 (MEM_ALIAS) returns ENOTTY on r54p0 → not critical for race
- CQS_WAIT enqueue may fail without proper kbase context → have fallback
- Race timing sensitive; may require multiple attempts

---

### TASK [T-002]: GPU Memory Mapping Analysis ⏳ pending

**Assigned to:** Rhea (CODER)  
**Priority:** critical  
**Status:** pending (blocked on T-001 confirmation)

#### Inputs

- mali_kbase memory allocation code (r54p0)
- KBASE_IOCTL_MEM_ALLOC interface
- KBASE_IOCTL_MEM_COMMIT interface  
- Buddy allocator behavior for high-order pages
- KBASE_MEM_SAME_VA flag usage

#### Expected Output

- GPU memory allocation that reclaims UAF page reliably
- Userspace mmap of GPU memory with CPU access
- Proof of page reuse (physical address tracking via pagemap)
- Success rate metrics for page reclaim

#### Verification

- [ ] /proc/self/pagemap shows identical physical page before/after
- [ ] Write to GPU memory affects CPU-visible data
- [ ] Physical PFN tracking confirms same page reused
- [ ] High-order page (order-0) allocation succeeds

#### Dependencies

- T-001 (race trigger confirmed)

---

### TASK [T-003]: Kernel Debugging & UAF Validation ⏳ pending

**Assigned to:** Silas (DEBUGGER)  
**Priority:** critical  
**Status:** pending (blocked on T-001, T-002)

#### Inputs

- Pixel 6/7/8/9 test devices with test kernels
- KGDB setup for remote debugging
- KASAN-enabled kernel config
- Device tree and kernel symbols

#### Expected Output

- Kernel crash dump analysis (KASAN report)
- UAF confirmation via KASAN (exact line numbers)
- Physical page tracking (PFN before/after)
- Buddy allocator state at time of UAF
- Race window size measurement

#### Verification

- [ ] KASAN report confirms UAF in `kbasep_csf_cpu_queue_dump_buffer+0x1d4`
- [ ] KGDB shows freed page access from GPU path
- [ ] Page refcount analysis shows double-free
- [ ] Race window precisely measured (not just 3s timeout)

#### Dependencies

- T-001 (race trigger confirmed)
- T-002 (GPU reclaim working)

---

### TASK [T-004]: Page Table Manipulation Primitive ⏳ pending

**Assigned to:** Vega (REVERSE-ENGINEER)  
**Priority:** high  
**Status:** pending (blocked on T-002, T-003)

#### Inputs

- ARM64 MMU structure (4KB pages, 48-bit VA)
- Mali GPU page table management
- init_cred physical address (from kallsyms)
- Kernel text base address
- modprobe_path variable address
- TTBR0_EL1 and TTBR1_EL1 layout

#### Expected Output

- PTE modification technique (remap any physical → any virtual)
- Arbitrary physical read/write primitive
- Root credential overwrite method
- SELinux bypass technique
- TLB shootdown handling

#### Verification

- [ ] Can read kernel memory from userspace (e.g., read init_cred)
- [ ] uid=0 after exploit (full root)
- [ ] getuid() returns 0
- [ ] Can disable SELinux (setenforce 0 equivalent)
- [ ] Can execute arbitrary commands as root

#### Dependencies

- T-002 (GPU page reclaim working)
- T-003 (UAF validation complete)

---

### TASK [T-005]: Full Exploit Integration ⏳ pending

**Assigned to:** Orion (REVERSE-ENGINEER)  
**Priority:** high  
**Status:** pending (blocked on all prior tasks)

#### Inputs

- All previous task outputs
- Android security patch analysis
- Device-specific offsets (Pixel 6/7/8/9)
- Kernel version detection logic
- SELinux policy bypass

#### Expected Output

- Complete exploit chain (race → UAF → root)
- Root shell on target device
- SELinux fully disabled
- Reliable exploit across device variants
- Clean error handling and retry logic

#### Verification

- [ ] id → uid=0(root) gid=0(root)
- [ ] getuid() returns 0
- [ ] Can disable SELinux: `setenforce 0`
- [ ] Can spawn root shell
- [ ] Works on Pixel 6, 7, 8, 9 (at least one variant each)

#### Dependencies

- T-001, T-002, T-003, T-004 (all prior tasks)

---

## Timeline

### Immediate (Week 1)
- [x] Implement T-001 race trigger on test devices
- [x] Confirm double-free via KASAN/dmesg
- [ ] T-002: GPU page reclaim with >60% success rate

### Short-term (Week 2-3)
- [ ] T-002: Validate physical page reuse
- [ ] T-003: Debug with KGDB on rooted test devices
- [ ] T-003: Collect KASAN reports for analysis

### Medium-term (Week 4-6)
- [ ] T-004: Develop page table manipulation
- [ ] T-004: Achieve arbitrary physical R/W
- [ ] T-005: Integrate full exploit chain
- [ ] T-005: Test across Pixel 6/7/8/9 variants

### Long-term (Week 7+)
- [ ] T-005: Reliability improvements
- [ ] T-005: Clean release candidate
- [ ] Documentation and responsible disclosure prep

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Race timing too tight | High | Medium | Increase attempts, add jitter |
| KASAN prevents exploitation | High | High | Test on non-KASAN builds |
| Driver r54p0+ has additional checks | Medium | High | Fallback to older versions |
| GPU memory type mismatch | Medium | Medium | Test multiple alloc flags |
| Page reclaim fails consistently | Low | High | Add alternative reclaim methods |

---

## Test Matrix

| Device | Android | Kernel | Mali Driver | Status | Notes |
|--------|---------|--------|-------------|--------|-------|
| Pixel 9 (Tokay) | 14 | 6.1.134 | r54p0 | 🔄 testing | Primary target |
| Pixel 8 Pro | 14 | 6.1.x | r53p0 | ⏳ pending | Secondary target |
| Pixel 7 Pro | 13 | 5.10.x | r53p0 | ⏳ pending | Legacy target |
| Pixel 6 Pro | 13 | 5.10.x | r52p0 | ⏳ pending | Legacy target |

---

## Resources

- [Research Log](research_logs/cve-2025-6349-8045-research.md) (610 lines)
- [Patch Diff Analysis](references/)
- [Exploit Patterns](references/) (GHSL-2024-356, GHSL-2023-005)
- [Debugging Guide](references/android_kernel_debugging.md)