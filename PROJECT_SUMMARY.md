# Shaby's Tech House — CVE-2025-6349/8045 Exploitation Project
## Google Pixel Mali GPU Kernel Driver → Root Privilege Escalation

**Target:** Pixel 9 (Tokay), Android 16, Kernel 5.10, Mali r53p0-r54p1  
**CVEs:** CVE-2025-6349, CVE-2025-8045 (CWE-416 Use-After-Free)  
**Severity:** High (CVSS 7.x)

---

## Quick Start

```bash
cd /home/unlockerplus/.kilo/skills/shaby-tech-bug-hunter
make                    # Build POC
./run_test.sh           # Run full test (requires device)
```

---

## What Was Delivered

### 1. POC Exploit (`poc_cve_2025_6349_8045.c`)
- Race condition trigger via GPU queue manipulation
- GPU memory allocation to reclaim freed pages  
- Page reuse verification (UAF confirmation)
- Framework for privilege escalation

**Binary:** `mali_uaf_poc` (796KB, ARM64, static)

### 2. Build System (`Makefile`)
- GCC cross-compiler (aarch64-linux-gnu-gcc)
- Alternative NDK build instructions
- Automated deployment targets

### 3. Test Automation (`run_test.sh`)
- Device verification
- POC deployment  
- Exploit execution
- dmesg analysis
- Privilege checking

### 4. Research Documentation
- `research_logs/cve-2025-6349-8045-research.md` — Full technical analysis
- `references/android_kernel_debugging.md` — KGDB/KASAN guide
- `references/mali_driver_analysis.md` — Mali exploit patterns
- `references/cve_research_sources.md` — 15+ research sources

### 5. Team Tasks (`research_logs/TASK-ASSIGNMENTS.md`)
- T-001 to T-006 assignments with priorities
- 6-person team structure

### 6. Reference Materials (`references/`)
- Mali driver analysis
- Historical CVEs
- Exploitation techniques

---

## Vulnerability Overview

**Root Cause:** Double-free in `kbasep_csf_cpu_queue_dump_print()` race condition

**Race Window:** 3-second timeout in CPU queue dump

**Exploitation Path:**
```
Double-free (race) → Page reclaim (GPU) → UAF (mmap) → 
Page table corruption → Arbitrary kernel R/W → 
init_cred overwrite → Root shell
```

**Evidence:** KASAN reports `slab-use-after-free` or `double-free`

---

## Testing on Pixel 9 (Tokay)

```bash
# 1. Build
make

# 2. Deploy and run
adb push mali_uaf_poc /data/local/tmp/
adb shell chmod +x /data/local/tmp/mali_uaf_poc
adb shell /data/local/tmp/mali_uaf_poc

# 3. Check for UAF
adb shell dmesg | grep -iE "kasan|use-after-free|double-free"

# 4. Verify root
adb shell id
# Expected: uid=0(root) gid=0(root)
```

Or use automated script:
```bash
./run_test.sh
```

---

## Key Technical Details

### Why It Works

1. **kmalloc-large pages** use buddy allocator (not slab)
2. **GPU memory** also uses buddy allocator  
3. **Same physical page** can be reclaimed
4. **GPU pages mmap'd to userspace** → arbitrary R/W
5. **Page table manipulation** → kernel code execution

### The Race

```
Thread 1:                          Thread 2:
  enqueue CQS_WAIT+FENCE
  → 3s timeout                     
                                    dump_buffer()
                                    → kfree(old) [1st]
                                    → kmalloc_large()
                                    → kfree(new) [2nd] ← DOUBLE FREE!
  TIMEOUT!                         → pointer dangling
  → skip processing
  → status = COMPLETE
  
  Later: kfree(dangling) ← Confirmed!
```

---

## Verification Checklist

| Check | Command | Expected |
|-------|---------|----------|
| Build | `make` | `mali_uaf_poc` binary (796KB) |
| Race | `dmesg \| grep double-free` | Double-free confirmed |
| UAF | `dmesg \| grep kasan` | slab-use-after-free |
| Page reclaim | POC output | "UAF CONFIRMED" |
| Root | `adb shell id` | `uid=0(root)` |
| SELinux | `adb shell getenforce` | `Permissive` |

---

## Known Limitations

- Requires Mali GPU (not Adreno)
- Driver version r53p0-r54p1
- KASAN may detect exploit
- SELinux enforcing mode blocks post-exploit
- KPTI separates kernel/user pages
- ARM MTE may detect corruption

---

## References

- Dawn's Lab: https://dawnslab.jd.com/Pixel_9_Pro_EoP/
- ARM Advisory: CVE-2025-6349/8045
- Android Bulletin: December 2025 (A-428702264, A-443063131)
- GHSL-2024-356: CVE-2025-0072 (similar technique)
- GHSL-2023-005: Pixel 6 Mali UAF

---

## Team: Shaby's Tech House R&D

- Kael — Lead Researcher
- Jax — PoC Developer  
- Rhea — GPU Specialist
- Silas — Kernel Debugger
- Nyx — Instrumentation
- Orion — Reverse Engineer
- Vega — Page Table Analyst

**Classification:** Internal Research  
**Last Updated:** 2026-04-25
