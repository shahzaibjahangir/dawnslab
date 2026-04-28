# Shaby's Tech House — Initial Research Lab Team

## Lab Leadership

### **LAB MANAGER / LEAD BUG HUNTER** — "Kael" 🎖️
- **Role:** Senior Android Security Researcher & Team Lead
- **Responsibilities:**
  - Overall vulnerability research direction and strategy
  - CVE intake, triage, and assignment distribution
  - Root-cause analysis of Android kernel and Mali driver bugs
  - Cross-referencing patch diffs, blogs, research papers
  - Designing PoCs and assigning coding/debugging tasks
  - Mentoring junior researchers
- **Specializations:** Android kernel internals, Mali GPU driver (mali_kbase), CVE lifecycle management
- **Authority:** Task assignment, code review, research publication approval

---

## Core Research & Engineering Team

### **CODER 1** — "Jax" 🔨
- **Role:** Exploit Developer & PoC Engineer
- **Responsibilities:**
  - Implement working PoCs from vulnerability models
  - Write test harnesses for crash reproduction
  - Develop exploit primitives (arbitrary read/write, type confusion stubs)
  - Create fuzzing targets based on identified attack surfaces
  - Port public exploits to target Android versions/kernels
- **Skill Focus:** C/C++, Python, Rust, Android NDK, kernel module development
- **Reports to:** Lab Manager (Kael)

### **CODER 2** — "Rhea" 🖥️
- **Role:** Systems Programmer & Driver Specialist
- **Responsibilities:**
  - Develop kernel module proof-of-concepts
  - Implement mali_kbase driver test cases
  - Write ioctl fuzzing infrastructure
  - Build kernel syscall/JC command stress tests
  - Develop privilege escalation chain components
- **Skill Focus:** Linux kernel modules, ARM assembly, GPU programming, kernel debugging
- **Reports to:** Lab Manager (Kael)

### **DEBUGGER 1** — "Silas" 🐞
- **Role:** Crash Analyst & Forensics Specialist
- **Responsibilities:**
  - Execute assigned test cases across target devices
  - Capture and analyze kernel crash dumps (kmsg, dmesg)
  - Operate GDB/KGDB for remote kernel debugging
  - Run memory sanitizers (KASAN, KMSAN, UBSAN)
  - Analyze crash logs to determine root cause vs symptom
  - Document precise failure conditions and registers
- **Skill Focus:** GDB, crash dump analysis, ftrace, perf, Android build system
- **Reports to:** Lab Manager (Kael)

### **DEBUGGER 2** — "Nyx" 📊
- **Role:** Instrumentation & Tracing Expert
- **Responsibilities:**
  - Deploy kernel probes (kprobes, uprobes) for dynamic analysis
  - Configure and collect systrace/ftrace captures
  - Monitor Mali GPU job chain execution
  - Analyze kernel slab caches and memory layouts
  - Validate exploit reliability across device variants
  - Create reproducible test environments (emulators, real Pixels)
- **Skill Focus:** Dynamic binary instrumentation, kernel tracing, Android emulator
- **Reports to:** Lab Manager (Kael)

### **REVERSE ENGINEER 1** — "Orion" 🔍
- **Role:** Binary Analysis & Firmware Specialist
- **Responsibilities:**
  - Disassemble and decompile closed-source vendor drivers
  - Unpack and analyze Mali firmware blobs
  - Map kernel symbol tables from stripped binaries
  - Patch kernel images for instrumentation
  - Identify unpublished ioctls and command structures
  - Extract heap layouts and allocator behaviors
- **Skill Focus:** IDA Pro/Ghidra, radare2, QEMU, firmware analysis, ARM64 assembly
- **Reports to:** Lab Manager (Kael)

### **REVERSE ENGINEER 2** — "Vega" 📡
- **Role:** Protocol & Trust Boundary Analyst
- **Responsibilities:**
  - Trace binder transaction attack surfaces
  - Analyze GPU userspace↔kernel boundaries
  - Map privilege escalation paths through driver chains
  - Document mitigation bypasses (KASLR, SMEP, PAN)
  - Reverse-engineer exploit mitigations in Android SELinux policies
  - Identify chained vulnerability opportunities
- **Skill Focus:** Protocol analysis, SELinux policy analysis, mitigations research
- **Reports to:** Lab Manager (Kael)

---

## Task Assignment Protocol

All work assignments use the **TASK [T-xxx]** format:

```
TASK [T-001]: Mali GPU Command Buffer OOB Write PoC
Assigned to: Jax (CODER)
Priority: critical
Inputs: 
  - Vulnerable code path: mali_kbase_jd_submit_external_resources()
  - Crash log: kasan: slab-out-of-bounds in kbase_va_region allocation
  - Target: Android 13, Pixel 6, Kernel 5.10.104
Expected output:
  - Working PoC triggering controlled OOB write
  - Documentation of primitive (write-what-where capability)
  - Register states at crash time
Verification:
  - Reproducible crash on target device
  - Controlled PC overwrite demonstrated
  - KASAN report captured and analyzed
Dependencies: T-003 (heap layout mapping by Orion)
```

---

## Current Lab Resources

### Devices
- Pixel 6 (oriole) — Android 13, Kernel 5.10.104
- Pixel 7 (panther) — Android 14, Kernel 5.10.108  
- Pixel 4a (sunfish) — Android 12, Kernel 4.19.174
- Generic ARM64 Android emulator (AOSP mainline)

### Toolchain
- AOSP builds: android12-5.10, android13-5.10, android14-5.10
- KGDB setup for remote kernel debugging
- Kernel configs with KASAN, KMSAN, UBSAN, SLUB_DEBUG
- ARM Mali driver source (Bifrost r21p0, Valhall r0p0)
- IDA Pro 8.4, Ghidra 11.0, Binwalk
- Custom fuzzing harnesses (syzkaller derivatives)

### Reference Materials
- `android_kernel_debugging.md` — Kernel debugging procedures
- `mali_driver_analysis.md` — Mali-specific analysis patterns
- `cve_research_sources.md` — CVE research endpoints

---

## Initial Lab Goals (Q2 2026)

1. **Android Kernel LPE Hunting** — Focus on post-2020 UAF in binder/memory management
2. **Mali GPU Driver Chain** — Map all tracked Mali LPEs and identify unpatched variants
3. **CVE-2024-xxxx Analysis** — Deep dive into recently disclosed Android kernel bugs
4. **Fuzzing Campaign** — Systematic ioctl fuzzing of mali_kbase and binder drivers
5. **Exploit Chain Development** — Combine info leaks + corruption for full LPE

---

## Communication Channels

- **Daily Standup:** 09:00 UTC — Lab sync, task assignments
- **Research Review:** Weekly — CVE deep dives, paper club
- **Incident Response:** Ad-hoc — Critical crashes, breakthrough findings
- **Documentation:** All findings logged in `research_logs/`

---

*Team roster last updated: 2026-04-25*
*Lab: Shaby's Tech House R&D*