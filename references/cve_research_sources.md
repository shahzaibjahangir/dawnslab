# CVE Research Sources & Search Patterns

## Overview
Comprehensive guide to researching Android kernel and Mali driver CVEs, including data sources, search strategies, and validation techniques.

## Primary Data Sources

### 1. National Vulnerability Database (NVD)
- **Base URL:** `https://nvd.nist.gov/vuln/detail/`
- **Format:** `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN`
- **CVSS Scores:** Provides CVSS v2 and v3 scores
- **CPE Mapping:** Affected product versions
- **References:** Links to vendor advisories, patches, exploits

**Search Pattern:**
```python
def fetch_nvd(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    # Parse CVSS vector, descriptions, references
```

### 2. MITRE CVE Database
- **Base URL:** `https://cve.mitre.org/cgi-bin/cvename.cgi?name=`
- **Alternate:** `https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-NNNNN`
- **Details:** Original CVE description, references, assigner

### 3. Android Security Bulletins
- **URL:** `https://source.android.com/docs/security/bulletin`
- **Monthly:** A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z
- **Categories:** Critical, High, Moderate, Low
- **Components:** Framework, System, Vendor, Kernel, etc.
- **Patch Level:** YYYY-MM-DD format

**Search for specific CVE:**
```bash
# Check which bulletin contains CVE
grep -r "CVE-2024-XXXX" security-bulletin-*.md
```

### 4. Android Git / AOSP Gerrit
- **Base URL:** `https://android.googlesource.com/`
- **Search Commits:** `https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline`
- **Patch Search:** Use Gerrit query: `status:merged CVE-2024-XXXX`
- **Direct Commit View:** `https://android.googlesource.com/kernel/common/+/COMMIT_HASH`

**Key Repositories:**
- `kernel/common/` — Common Android kernel
- `kernel/` — Device-specific kernels  
- `platform/system/core/` — Core Android userspace
- `platform/system/sepolicy/` — SELinux policies

### 5. ARM Mali Security Advisories
- **URL:** `https://developer.arm.com/security-notices`
- **Filter:** Graphics, Mali, GPU
- **Details:** CVE ID, affected versions, patches, workarounds

### 6. Qualcomm Security Bulletins
- **URL:** `https://www.qualcomm.com/company/product-security/bulletins`
- **Focus:** Snapdragon, Adreno, GPU drivers
- **CVE Lists:** Per bulletin date

### 7. Samsung Security Response
- **URL:** `https://security.samsung.com/`
- **Mobile:** Android device vulnerabilities
- **Exynos:** Samsung-specific SoC issues

### 8. Google Project Zero
- **Blog:** `https://googleprojectzero.blogspot.com/`
- **Search:** "mali", "android kernel", "cve"
- **Issues:** `https://bugs.chromium.org/p/project-zero/issues/list?q=label%3Asecurity-bug`
- **In-the-wild:** Active exploitation reports

### 9. GitHub PoC Repository Search
- **URL:** `https://github.com/search?q=CVE-YYYY-NNNNN+android`
- **Filters:** Stars, language, updated date
- **Quality indicators:** Test harness, reproduction steps, device targets

### 10. Exploit-DB
- **URL:** `https://www.exploit-db.com/`
- **Search:** CVE ID in title/description
- **Platform:** Linux, Android, ARM

### 11. PacketStorm Security
- **URL:** `https://packetstormsecurity.com/`
- **Search:** "android kernel", "mali", "cve"
- **Downloads:** Exploits, papers, tools

### 12. SSD Advisory
- **URL:** `https://ssd-disclosure.com/`
- **Search:** Vendor-specific advisories
- **Details:** Technical analysis, PoCs

### 13. IEEE Xplore / ACM Digital Library
- **Academic papers:** Android security, kernel exploitation
- **Search:** "Android kernel vulnerability", "Mali GPU security"
- **Recent:** Within last 2-3 years for current techniques

### 14. Black Hat / DEF CON Archives
- **URL:** `https://www.blackhat.com/`
- **Presentations:** Exploit techniques, vulnerability analysis
- **Tools/Advisories:** Published alongside talks

### 15. GitHub Repositories
- **Keywords:** `android-kernel-exploit`, `mali-kbase`, `cve-poc`
- **Stars:** >50 indicates quality/maintaned
- **Recent commits:** Active development/validation

## Search Workflow

### Phase 1: Basic CVE Identification
```
1. Query NVD:
   https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
   → Extract: CVSS, affected versions, CPE

2. Query Android Security Bulletin:
   https://source.android.com/docs/security/bulletin/YYYY-MM
   → Check AOSP patches, component affected

3. Query ARM Mali Advisories:
   https://developer.arm.com/security-notices
   → Check if GPU-related
```

### Phase 2: Patch Analysis
```
4. Search AOSP Git:
   https://android.googlesource.com/
   Query: CVE-YYYY-NNNNN
   → Get commit hash, review diff

5. Analyze diff:
   - File paths changed
   - Function names
   - Buggy line identification
   - Fix logic (bounds check? refcount? lock?)

6. Check ARM Mali:
   https://developer.arm.com/security-notices
   → Affected driver versions
```

### Phase 3: Public Intelligence
```
7. Google Project Zero:
   Search blog for CVE ID
   → Exploit technique, root cause, active exploitation

8. GitHub PoC Search:
   "CVE-YYYY-NNNNN android"
   → Review quality, test on device

9. Exploit-DB / PacketStorm:
   CVE in title
   → Download exploit, review technique
```

### Phase 4: Academic Research
```
10. Google Scholar:
    "CVE-YYYY-NNNNN" OR
    "Android kernel" + "Mali" + "vulnerability"
    → Recent papers on similar techniques

11. Black Hat archives:
    Year: YYYY, YYYY-1, YYYY-2
    → Talks on Android exploitation
```

## CVE Pattern Analysis

### Kernel Memory Corruption Pattern
```
CVE-YYYY-NNNNN: Android kernel [component] use-after-free
Severity: High/Critical
CVSS: 7.x - 8.x

Affected:
- Android kernel [version range]
- Devices: All/Pixel X
- Component: binder/mali/ext4

Fix:
- AOSP commit: hash
- Added: bounds check / refcount / lock
- Changed file: drivers/android/binder.c

Analysis priority: HIGH
→ Likely has public PoC
→ Check GitHub/Exploit-DB
```

### Mali GPU Driver Pattern
```
CVE-YYYY-NNNNN: ARM Mali kernel driver [type]
Severity: Critical
CVSS: 8.x - 9.x

Affected:
- Mali kernel driver [versions]
- Devices: Pixel / Samsung / etc.
- Component: mali_kbase

Fix:
- ARM advisory: ID
- Commit range: start..end
- Vulnerability: race / UAF / OOB

Analysis priority: CRITICAL
→ GPU driver = LPE potential
→ Check for chained exploits
```

## Research Log Template

```markdown
# CVE-YYYY-NNNNN Research Log

## Basic Info
- **CVE ID:** CVE-YYYY-NNNNN
- **Date assigned:** YYYY-MM-DD
- **Severity:** High/Critical (CVSS: X.X)
- **Component:** Android kernel / Mali driver / etc.

## 1. NVD Analysis
- [ ] Retrieved from NVD
- CVSS vector: ...
- Affected CPEs: ...
- References: ...

## 2. Android Security Bulletin
- [ ] Checked bulletin YYYY-MM
- [ ] Patch level found: YYYY-MM-DD
- [ ] Component: ...

## 3. AOSP Patch
- [ ] Commit found: abc1234
- [ ] Files changed: file1.c, file2.c
- [ ] Function: buggy_function()
- [ ] Fix type: bounds check / refcount / lock
- Diff saved: cve-YYYY-NNNNN.patch

## 4. Public Intelligence
- [ ] Project Zero blog: Y/N
- [ ] GitHub PoCs: N found
- [ ] Exploit-DB: Y/N
- [ ] Active exploitation: Y/N

## 5. Vulnerability Model
- **Bug type:** UAF / OOB / race / overflow
- **Trigger:** sys_ioctl / binder transaction / etc.
- **Primitive:** info leak / arbitrary write / LPE
- **Constraints:** race window / size limits / etc.

## 6. Task Assignment Plan
- [ ] Coders: PoC implementation
- [ ] Debuggers: Crash analysis
- [ ] Reverse engineers: Binary analysis

## Research Log Entries

### [YYYY-MM-DD HH:MM] — Initial intake
Action: Retrieved from NVD, found Android bulletin
Finding: Affects kernel 5.10, Pixel 6

### [YYYY-MM-DD HH:MM] — Patch analysis  
Action: Reviewed AOSP commit abc1234
Finding: Missing bounds check in function_X()
```

## Validation Checklist

When researching a CVE, verify:

- [ ] NVD entry retrieved (CVSS, references)
- [ ] Android Security Bulletin checked
- [ ] AOSP commit found and diff reviewed
- [ ] ARM Mali advisory checked (if GPU)
- [ ] Google Project Zero searched
- [ ] GitHub PoC search completed
- [ ] Exploit-DB search completed
- [ ] Academic papers reviewed (if recent)
- [ ] Public PoC tested (if available)
- [ ] Vulnerability model documented
- [ ] Tasks assigned to workers
- [ ] Research log updated

## Automation Scripts

### Quick CVE Lookup
```bash
#!/bin/bash
CVE=$1
echo "=== NVD ==="
curl -s "https://nvd.nist.gov/vuln/detail/$CVE" | grep -o 'CVSS.*' | head -5

echo "=== Android Bulletin ==="
curl -s "https://source.android.com/docs/security/bulletin" | grep -i "$CVE"

echo "=== AOSP Git ==="
curl -s "https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline" | grep -i "$CVE"

echo "=== GitHub PoCs ==="
open "https://github.com/search?q=$CVE+android"
```

### Download All Sources
```bash
#!/bin/bash
CVE=$1
mkdir -p research/$CVE

# NVD JSON
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE" > research/$CVE/nvd.json

# Android bulletin (approximate)
YEAR=$(echo $CVE | cut -d'-' -f2)
MONTH="01"  # You may need to search multiple months
curl -s "https://source.android.com/docs/security/bulletin/$YEAR-$MONTH" > research/$CVE/bulletin.html

# Google search for PoCs
curl -s "https://github.com/search?q=$CVE+android" > research/$CVE/github.html
```

## References

- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- Android Security: https://source.android.com/docs/security
- ARM Security: https://developer.arm.com/security-notices  
- Google Project Zero: https://googleprojectzero.blogspot.com
- Exploit-DB: https://www.exploit-db.com
- GitHub Advanced Search: https://github.com/search/advanced